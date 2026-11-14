#include "acc_native.h"
#include "acc_bytecode.h"
#include "acc_compiler.h"
#include "acc_runtime.h"
#include "filesystem.h"
#include "string_utils.h"

extern const uint8_t acc_runtime_start[];
extern const uint8_t acc_runtime_end[];

#define BYTECODE_LIMIT (ACC_MAX_CODE_SIZE * 2)
#define NATIVE_LIMIT (256 * 1024)
#define FIXUP_LIMIT (BYTECODE_LIMIT / 5)
#define UNSET 0xFFFFFFFFu
#define NO_DEPTH (-1)
#define SLOT_BYTES 8
#define GLOBAL_BYTES 4
#define SECTION_ALIGN 16
#define ELF_HEADER_SIZE 64
#define ELF_PHDR_SIZE 56
#define SEGMENT_FILE_OFFSET 0x1000
#define SEGMENT_ALIGN 0x1000
#define ET_EXEC 2
#define EM_X86_64 62
#define PT_LOAD 1
#define PF_RWX 7
#define SYS_EXIT_STATUS 1000
#define WRITE_CHUNK 4096

typedef struct {
    uint32_t native;
    uint32_t target;
} fixup_t;

static struct {
    const uint8_t* code;
    uint32_t code_size;
    uint32_t entry;
    uint64_t globals;
    uint64_t data;
    uint64_t code_base;
    uint8_t out[NATIVE_LIMIT];
    uint32_t length;
    uint32_t native_at[BYTECODE_LIMIT];
    int16_t depth[BYTECODE_LIMIT];
    int16_t argc_of[BYTECODE_LIMIT];
    uint32_t worklist[BYTECODE_LIMIT];
    fixup_t fixups[FIXUP_LIMIT];
    uint32_t fixup_count;
    bool overflow;
} tr;

/* bytecode reading */

static uint16_t u16_at(uint32_t pc) {
    return (uint16_t)(tr.code[pc] | (tr.code[pc + 1] << 8));
}

static uint32_t read_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t u32_at(uint32_t pc) {
    return read_le32(tr.code + pc);
}

static uint32_t instruction_length(uint8_t op) {
    switch (op) {
        case OP_PUSH: case OP_PUSHS: case OP_JMP: case OP_JZ: case OP_JNZ: return 5;
        case OP_LDL: case OP_STL: case OP_LDG: case OP_STG: case OP_ENTER: case OP_SYS: return 3;
        case OP_LDLI: case OP_STLI: case OP_LDGI: case OP_STGI: case OP_ADJL: case OP_ADJG: return 5;
        case OP_ADJLI: case OP_ADJGI: return 7;
        case OP_CALL: return 6;
        case OP_HALT: case OP_NEG: case OP_NOT: case OP_BNOT: case OP_RET: case OP_POP: case OP_DUP: return 1;
        default: return (op >= OP_ADD && op <= OP_GE) ? 1 : 0;
    }
}

static uint32_t jump_target(uint32_t pc) {
    return pc + 5 + u32_at(pc + 1);
}

/* stack depth, needed because HALT exits with the top of the stack only when there is one */

static int depth_change(uint32_t pc) {
    uint8_t op = tr.code[pc];
    switch (op) {
        case OP_PUSH: case OP_PUSHS: case OP_LDL: case OP_LDG: case OP_DUP: case OP_ADJL: case OP_ADJG: return 1;
        case OP_STLI: case OP_STGI: case OP_JZ: case OP_JNZ: case OP_POP: return -1;
        case OP_CALL: return 1 - tr.code[pc + 5];
        case OP_SYS: return 1 - tr.code[pc + 2];
        default: return (op >= OP_ADD && op <= OP_GE) ? -1 : 0;
    }
}

static bool visit(uint32_t pc, int depth, uint32_t* count, char* error) {
    if (pc >= tr.code_size) { string_copy(error, "bytecode jumps outside the code"); return false; }
    if (tr.depth[pc] == NO_DEPTH) {
        tr.depth[pc] = (int16_t)depth;
        tr.worklist[(*count)++] = pc;
        return true;
    }
    if (tr.depth[pc] != depth) { string_copy(error, "bytecode stack depth differs between paths"); return false; }
    return true;
}

static bool analyse_depth(char* error) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < tr.code_size; i++) tr.depth[i] = NO_DEPTH;
    if (!visit(tr.entry, 0, &count, error)) return false;
    for (uint32_t i = 0; i < tr.code_size; i++) {
        if (tr.argc_of[i] >= 0 && !visit(i, 0, &count, error)) return false;
    }
    while (count > 0) {
        uint32_t pc = tr.worklist[--count];
        uint8_t op = tr.code[pc];
        int next = tr.depth[pc] + depth_change(pc);
        if (next < 0) { string_copy(error, "bytecode pops an empty stack"); return false; }
        if (op == OP_RET || op == OP_HALT) continue;
        if ((op == OP_JMP || op == OP_JZ || op == OP_JNZ) && !visit(jump_target(pc), next, &count, error)) return false;
        if (op != OP_JMP && !visit(pc + instruction_length(op), next, &count, error)) return false;
    }
    return true;
}

static bool scan(char* error) {
    for (uint32_t i = 0; i < tr.code_size; i++) tr.argc_of[i] = -1;
    for (uint32_t pc = 0; pc < tr.code_size;) {
        uint32_t length = instruction_length(tr.code[pc]);
        if (length == 0 || pc + length > tr.code_size) { string_copy(error, "invalid bytecode instruction"); return false; }
        if (tr.code[pc] == OP_CALL) {
            uint32_t target = u32_at(pc + 1);
            if (target >= tr.code_size) { string_copy(error, "bytecode calls outside the code"); return false; }
            tr.argc_of[target] = tr.code[pc + 5];
        }
        pc += length;
    }
    return true;
}

/* machine code emission */

static void e8(uint8_t b) {
    if (tr.length >= NATIVE_LIMIT) { tr.overflow = true; return; }
    tr.out[tr.length++] = b;
}

static void e32(uint32_t v) {
    for (int i = 0; i < 4; i++) e8((uint8_t)(v >> (8 * i)));
}

static void bytes(const uint8_t* b, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) e8(b[i]);
}

#define EMIT(...) do { static const uint8_t seq[] = {__VA_ARGS__}; bytes(seq, sizeof(seq)); } while (0)

static int32_t local_disp(uint32_t slot) {
    return -(int32_t)(SLOT_BYTES * (slot + 1));
}

static uint32_t global_address(uint32_t slot) {
    return (uint32_t)(tr.globals + GLOBAL_BYTES * slot);
}

static void push_rax_extended(void) {
    EMIT(0x48, 0x63, 0xC0, 0x50);
}

// rel32 jumps and calls to bytecode offsets are patched once every offset has a native address
static void branch_to(uint32_t target) {
    if (tr.fixup_count < FIXUP_LIMIT) tr.fixups[tr.fixup_count++] = (fixup_t){tr.length, target};
    else tr.overflow = true;
    e32(0);
}

static void call_runtime(uint64_t address) {
    EMIT(0xB8);
    e32((uint32_t)address);
    EMIT(0xFF, 0xD0);
}

static void trap(uint32_t pc, uint32_t reason) {
    EMIT(0xBF);
    e32(pc);
    EMIT(0xBE);
    e32(reason);
    EMIT(0x48, 0x83, 0xE4, 0xF0);
    call_runtime(((const acc_runtime_header_t*)acc_runtime_start)->trap);
}

/* variables, every stack value is kept sign extended to 64 bits */

static void load_local(uint32_t slot) {
    EMIT(0x48, 0x63, 0x85);
    e32((uint32_t)local_disp(slot));
}

static void store_local_rax(uint32_t slot) {
    EMIT(0x48, 0x89, 0x85);
    e32((uint32_t)local_disp(slot));
}

static void load_global(uint32_t slot) {
    EMIT(0x48, 0x63, 0x04, 0x25);
    e32(global_address(slot));
}

static void store_global_eax(uint32_t slot) {
    EMIT(0x89, 0x04, 0x25);
    e32(global_address(slot));
}

// Pops an index into rcx, checks it against the array length and leaves the element address in rdx
static void element_address(uint32_t pc, bool global, uint32_t slot, uint32_t length) {
    EMIT(0x59, 0x81, 0xF9);
    e32(length);
    EMIT(0x72);
    uint32_t skip = tr.length;
    e8(0);
    trap(pc, ACC_TRAP_INDEX);
    tr.out[skip] = (uint8_t)(tr.length - skip - 1);
    if (global) {
        EMIT(0x48, 0x8D, 0x14, 0x8D);
        e32(global_address(slot));
    } else {
        EMIT(0x48, 0x8D, 0x95);
        e32((uint32_t)local_disp(slot));
        EMIT(0x48, 0xC1, 0xE1, 0x03, 0x48, 0x29, 0xCA);
    }
}

static void store_element_rax(bool global) {
    if (global) EMIT(0x89, 0x02);
    else EMIT(0x48, 0x89, 0x02);
}

static void op_indexed(uint32_t pc, uint8_t op) {
    bool global = op == OP_LDGI || op == OP_STGI;
    bool store = op == OP_STLI || op == OP_STGI;
    if (store) EMIT(0x58, 0x48, 0x89, 0xC6);
    element_address(pc, global, u16_at(pc + 1), u16_at(pc + 3));
    if (!store) {
        EMIT(0x48, 0x63, 0x02, 0x50);
        return;
    }
    EMIT(0x48, 0x89, 0xF0);
    store_element_rax(global);
    EMIT(0x50);
}

static void op_adjust(uint32_t pc, uint8_t op) {
    bool global = op == OP_ADJG || op == OP_ADJGI;
    bool indexed = op == OP_ADJLI || op == OP_ADJGI;
    uint32_t slot = u16_at(pc + 1);
    int8_t delta = (int8_t)tr.code[pc + (indexed ? 5 : 3)];
    bool post = tr.code[pc + (indexed ? 6 : 4)] != 0;
    if (indexed) {
        element_address(pc, global, slot, u16_at(pc + 3));
        EMIT(0x48, 0x63, 0x02);
    } else if (global) {
        load_global(slot);
    } else {
        load_local(slot);
    }
    EMIT(0x48, 0x89, 0xC1, 0x83, 0xC0);
    e8((uint8_t)delta);
    EMIT(0x48, 0x63, 0xC0);
    if (indexed) store_element_rax(global);
    else if (global) store_global_eax(slot);
    else store_local_rax(slot);
    if (post) EMIT(0x51);
    else EMIT(0x50);
}

/* arithmetic */

static void op_divide(uint32_t pc, bool remainder) {
    EMIT(0x59, 0x58, 0x85, 0xC9, 0x75);
    uint32_t skip = tr.length;
    e8(0);
    trap(pc, ACC_TRAP_DIVIDE);
    tr.out[skip] = (uint8_t)(tr.length - skip - 1);
    // INT_MIN / -1 would fault in idiv, dividing by -1 is a negation that wraps
    EMIT(0x83, 0xF9, 0xFF, 0x75);
    if (remainder) EMIT(0x04, 0x31, 0xC0, 0xEB, 0x05, 0x99, 0xF7, 0xF9, 0x89, 0xD0);
    else EMIT(0x04, 0xF7, 0xD8, 0xEB, 0x03, 0x99, 0xF7, 0xF9);
    push_rax_extended();
}

static void op_binary(uint32_t pc, uint8_t op) {
    static const uint8_t compare_set[] = {0x94, 0x95, 0x9C, 0x9E, 0x9F, 0x9D};
    if (op == OP_DIV || op == OP_MOD) { op_divide(pc, op == OP_MOD); return; }
    EMIT(0x59, 0x58);
    switch (op) {
        case OP_ADD: EMIT(0x01, 0xC8); break;
        case OP_SUB: EMIT(0x29, 0xC8); break;
        case OP_MUL: EMIT(0x0F, 0xAF, 0xC1); break;
        case OP_AND: EMIT(0x21, 0xC8); break;
        case OP_OR: EMIT(0x09, 0xC8); break;
        case OP_XOR: EMIT(0x31, 0xC8); break;
        case OP_SHL: EMIT(0xD3, 0xE0); break;
        case OP_SHR: EMIT(0xD3, 0xF8); break;
        default:
            EMIT(0x39, 0xC8, 0x0F);
            e8(compare_set[op - OP_EQ]);
            EMIT(0xC0, 0x0F, 0xB6, 0xC0);
            break;
    }
    push_rax_extended();
}

static void op_unary(uint8_t op) {
    EMIT(0x58);
    if (op == OP_NEG) EMIT(0xF7, 0xD8);
    else if (op == OP_BNOT) EMIT(0xF7, 0xD0);
    else EMIT(0x85, 0xC0, 0x0F, 0x94, 0xC0, 0x0F, 0xB6, 0xC0);
    push_rax_extended();
}

/* control flow */

static void op_jump(uint32_t pc, uint8_t op) {
    if (op == OP_JMP) {
        EMIT(0xE9);
    } else {
        EMIT(0x58, 0x85, 0xC0, 0x0F);
        e8(op == OP_JZ ? 0x84 : 0x85);
    }
    branch_to(jump_target(pc));
}

static void op_call(uint32_t pc) {
    uint32_t argc = tr.code[pc + 5];
    EMIT(0xE8);
    branch_to(u32_at(pc + 1));
    if (argc) {
        EMIT(0x48, 0x81, 0xC4);
        e32(argc * SLOT_BYTES);
    }
    EMIT(0x50);
}

// Arguments sit above the return address with the last one nearest, they are copied into the first slots
static void op_enter(uint32_t pc) {
    uint32_t argc = tr.argc_of[pc] > 0 ? (uint32_t)tr.argc_of[pc] : 0;
    uint32_t count = u16_at(pc + 1);
    uint32_t slots = count > argc ? count : argc;
    EMIT(0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC);
    e32(slots * SLOT_BYTES);
    for (uint32_t i = 0; i < argc; i++) {
        EMIT(0x48, 0x8B, 0x85);
        e32(2 * SLOT_BYTES + SLOT_BYTES * (argc - 1 - i));
        store_local_rax(i);
    }
    if (slots == argc) return;
    EMIT(0x48, 0x8D, 0xBD);
    e32((uint32_t)local_disp(slots - 1));
    EMIT(0xB9);
    e32(slots - argc);
    EMIT(0x31, 0xC0, 0xF3, 0x48, 0xAB);
}

static void op_sys(uint32_t pc) {
    uint32_t id = tr.code[pc + 1], argc = tr.code[pc + 2];
    EMIT(0x49, 0x89, 0xE4, 0x48, 0x83, 0xE4, 0xF0, 0xBF);
    e32(id);
    EMIT(0xBE);
    e32(argc);
    EMIT(0x4C, 0x89, 0xE2, 0xB9);
    e32(pc);
    call_runtime(((const acc_runtime_header_t*)acc_runtime_start)->sys);
    EMIT(0x4C, 0x89, 0xE4);
    if (argc) {
        EMIT(0x48, 0x81, 0xC4);
        e32(argc * SLOT_BYTES);
    }
    push_rax_extended();
}

static void op_halt(uint32_t pc) {
    if (tr.depth[pc] > 0) EMIT(0x5F);
    else EMIT(0x31, 0xFF);
    EMIT(0xB8);
    e32(SYS_EXIT_STATUS);
    EMIT(0x0F, 0x05);
}

static void op_variable(uint32_t pc, uint8_t op) {
    uint32_t slot = u16_at(pc + 1);
    switch (op) {
        case OP_LDL: load_local(slot); EMIT(0x50); break;
        case OP_LDG: load_global(slot); EMIT(0x50); break;
        case OP_STL: EMIT(0x48, 0x8B, 0x04, 0x24); store_local_rax(slot); break;
        default: EMIT(0x48, 0x8B, 0x04, 0x24); store_global_eax(slot); break;
    }
}

static void translate_one(uint32_t pc) {
    uint8_t op = tr.code[pc];
    switch (op) {
        case OP_HALT: op_halt(pc); break;
        case OP_PUSH: EMIT(0x68); e32(u32_at(pc + 1)); break;
        case OP_PUSHS: EMIT(0x68); e32(u32_at(pc + 1) | ACC_STRING_TAG); break;
        case OP_LDL: case OP_STL: case OP_LDG: case OP_STG: op_variable(pc, op); break;
        case OP_LDLI: case OP_STLI: case OP_LDGI: case OP_STGI: op_indexed(pc, op); break;
        case OP_ADJL: case OP_ADJG: case OP_ADJLI: case OP_ADJGI: op_adjust(pc, op); break;
        case OP_NEG: case OP_NOT: case OP_BNOT: op_unary(op); break;
        case OP_JMP: case OP_JZ: case OP_JNZ: op_jump(pc, op); break;
        case OP_CALL: op_call(pc); break;
        case OP_ENTER: op_enter(pc); break;
        case OP_RET: EMIT(0x58, 0xC9, 0xC3); break;
        case OP_POP: EMIT(0x48, 0x83, 0xC4, 0x08); break;
        case OP_DUP: EMIT(0xFF, 0x34, 0x24); break;
        case OP_SYS: op_sys(pc); break;
        default: op_binary(pc, op); break;
    }
}

static bool translate(char* error) {
    tr.length = 0;
    tr.fixup_count = 0;
    tr.overflow = false;
    for (uint32_t i = 0; i < tr.code_size; i++) tr.native_at[i] = UNSET;
    for (uint32_t pc = 0; pc < tr.code_size; pc += instruction_length(tr.code[pc])) {
        tr.native_at[pc] = tr.length;
        translate_one(pc);
    }
    if (tr.overflow) { string_copy(error, "translated program is larger than the native code buffer"); return false; }
    for (uint32_t i = 0; i < tr.fixup_count; i++) {
        uint32_t target = tr.native_at[tr.fixups[i].target];
        if (target == UNSET) { string_copy(error, "bytecode branches into the middle of an instruction"); return false; }
        uint32_t rel = target - (tr.fixups[i].native + 4);
        for (int b = 0; b < 4; b++) tr.out[tr.fixups[i].native + b] = (uint8_t)(rel >> (8 * b));
    }
    return true;
}

/* output file */

static bool write_bytes(fs_file_handle_t* file, const void* data, uint32_t length) {
    return filesystem_write_file(file, data, length) == length;
}

static bool write_zeros(fs_file_handle_t* file, uint32_t length) {
    static const uint8_t zeros[WRITE_CHUNK];
    while (length > 0) {
        uint32_t n = length < WRITE_CHUNK ? length : WRITE_CHUNK;
        if (!write_bytes(file, zeros, n)) return false;
        length -= n;
    }
    return true;
}

static void elf_headers(uint8_t* h, uint64_t segment_size) {
    memset(h, 0, ELF_HEADER_SIZE + ELF_PHDR_SIZE);
    h[0] = 0x7F; h[1] = 'E'; h[2] = 'L'; h[3] = 'F';
    h[4] = 2; h[5] = 1; h[6] = 1;
    *(uint16_t*)(h + 16) = ET_EXEC;
    *(uint16_t*)(h + 18) = EM_X86_64;
    *(uint32_t*)(h + 20) = 1;
    *(uint64_t*)(h + 24) = ((const acc_runtime_header_t*)acc_runtime_start)->entry;
    *(uint64_t*)(h + 32) = ELF_HEADER_SIZE;
    *(uint16_t*)(h + 52) = ELF_HEADER_SIZE;
    *(uint16_t*)(h + 54) = ELF_PHDR_SIZE;
    *(uint16_t*)(h + 56) = 1;
    uint8_t* p = h + ELF_HEADER_SIZE;
    *(uint32_t*)p = PT_LOAD;
    *(uint32_t*)(p + 4) = PF_RWX;
    *(uint64_t*)(p + 8) = SEGMENT_FILE_OFFSET;
    *(uint64_t*)(p + 16) = ACC_RUNTIME_BASE;
    *(uint64_t*)(p + 24) = ACC_RUNTIME_BASE;
    *(uint64_t*)(p + 32) = segment_size;
    *(uint64_t*)(p + 40) = segment_size;
    *(uint64_t*)(p + 48) = SEGMENT_ALIGN;
}

// Segment layout: runtime, globals, string data, translated code
static bool write_program(const char* output, const uint8_t* data, uint32_t data_size, char* error) {
    acc_runtime_header_t header = *(const acc_runtime_header_t*)acc_runtime_start;
    uint32_t blob = (uint32_t)(acc_runtime_end - acc_runtime_start);
    // Runtime bss and the globals are written as zeros so the segment is one contiguous file range
    uint32_t before_data = (uint32_t)(tr.data - ACC_RUNTIME_BASE) - blob;
    header.program = tr.code_base + tr.native_at[tr.entry];
    header.data = tr.data;
    header.data_size = data_size;
    uint64_t segment = tr.code_base - ACC_RUNTIME_BASE + tr.length;
    uint8_t headers[ELF_HEADER_SIZE + ELF_PHDR_SIZE];
    elf_headers(headers, segment);
    if (filesystem_file_exists(output) && !filesystem_delete_file(output)) { string_copy(error, "output path exists and is not a file"); return false; }
    if (!filesystem_create_file(output)) { string_copy(error, "cannot create the output file"); return false; }
    fs_file_handle_t* file = filesystem_open_file(output, true);
    if (!file) { string_copy(error, "cannot open the output file"); return false; }
    bool ok = write_bytes(file, headers, sizeof(headers)) && write_zeros(file, SEGMENT_FILE_OFFSET - sizeof(headers)) &&
              write_bytes(file, &header, sizeof(header)) && write_bytes(file, acc_runtime_start + sizeof(header), blob - sizeof(header)) &&
              write_zeros(file, before_data) &&
              write_bytes(file, data, data_size) && write_zeros(file, (uint32_t)(tr.code_base - tr.data - data_size)) &&
              write_bytes(file, tr.out, tr.length);
    filesystem_close_file(file);
    if (!ok) string_copy(error, "the output file could not be written in full");
    return ok;
}

bool acc_native_write(const uint8_t* image, uint32_t size, const char* output, char* error) {
    if (size < ACC_HEADER_SIZE || image[3] != ACC_MAGIC_3) { string_copy(error, "not an ACC1 bytecode image"); return false; }
    tr.entry = read_le32(image + 4);
    tr.code_size = read_le32(image + 8);
    uint32_t data_size = read_le32(image + 12);
    uint32_t globals = read_le32(image + 16);
    if (tr.code_size > BYTECODE_LIMIT || tr.entry >= tr.code_size) { string_copy(error, "bytecode image is malformed"); return false; }
    tr.code = image + ACC_HEADER_SIZE;
    const uint8_t* data = tr.code + tr.code_size;
    const acc_runtime_header_t* runtime = (const acc_runtime_header_t*)acc_runtime_start;
    tr.globals = ACC_RUNTIME_BASE + ALIGN_UP(runtime->end - ACC_RUNTIME_BASE, SECTION_ALIGN);
    tr.data = ALIGN_UP(tr.globals + (uint64_t)globals * GLOBAL_BYTES, SECTION_ALIGN);
    tr.code_base = ALIGN_UP(tr.data + data_size, SECTION_ALIGN);
    if (!scan(error) || !analyse_depth(error) || !translate(error)) return false;
    return write_program(output, data, data_size, error);
}
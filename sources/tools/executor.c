#include "executor.h"
#include "acc_bytecode.h"
#include "filesystem.h"
#include "terminal.h"
#include "input_manager.h"
#include "string_utils.h"
#include "blackjack.h"
#include "roulette.h"
#include "types.h"

#define VM_STACK_SIZE 1024
#define VM_MAX_FRAMES 64
#define VM_LOCAL_SLOTS 4096
#define VM_GLOBAL_SLOTS 4096
#define VM_MAX_FILES 4
#define VM_INSTRUCTION_LIMIT 100000000u
#define VM_FORMAT_ARGS 16
#define ERROR_TEXT 256
#define NATIVE_NAME_OFFSET 4
#define FILE_HANDLE_BASE 1

typedef struct {
    uint32_t return_pc;
    uint32_t base;
} frame_t;

typedef struct {
    const char* name;
    void (*entry_point)(void*);
} native_program_t;

static const native_program_t natives[] = {
    {"blackjack", (void (*)(void*))blackjack_run},
    {"roulette", (void (*)(void*))roulette_run},
    {NULL, NULL}
};

static struct {
    uint8_t image[FS_TOOL_BUFFER_SIZE];
    uint32_t image_size;
    const uint8_t* code;
    uint32_t code_size;
    const uint8_t* data;
    uint32_t data_size;
    uint32_t entry;
    uint32_t global_count;
    const native_program_t* native;

    int32_t stack[VM_STACK_SIZE];
    uint32_t sp;
    frame_t frames[VM_MAX_FRAMES];
    uint32_t frame_count;
    int32_t locals[VM_LOCAL_SLOTS];
    uint32_t locals_top;
    int32_t globals[VM_GLOBAL_SLOTS];
    fs_file_handle_t* files[VM_MAX_FILES];

    uint32_t pc;
    uint32_t op_pc;
    bool running;
    bool exited;
    int32_t exit_code;
    char error[ERROR_TEXT];
    bool has_error;
} vm;

static uint8_t native_data[sizeof(blackjack_game_t) > sizeof(roulette_game_t) ? sizeof(blackjack_game_t) : sizeof(roulette_game_t)];

static void fail(const char* message) {
    if (vm.has_error) return;
    vm.has_error = true;
    vm.running = false;
    string_copy(vm.error, message);
}

// Runtime errors carry the offset of the instruction that raised them
static void trap(const char* message) {
    char text[ERROR_TEXT];
    const char hex[] = "0123456789abcdef";
    string_copy(text, "runtime error at 0x");
    uint32_t pos = string_length(text);
    for (int shift = 12; shift >= 0; shift -= 4) text[pos++] = hex[(vm.op_pc >> shift) & 0xF];
    text[pos] = '\0';
    string_concat_n(text, ": ", sizeof(text));
    string_concat_n(text, message, sizeof(text));
    fail(text);
}

static uint32_t read_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool fetch_ok(uint32_t bytes) {
    if (vm.pc + bytes > vm.code_size) {
        trap("instruction runs past the end of the code");
        return false;
    }
    return true;
}

static uint8_t fetch8(void) {
    return fetch_ok(1) ? vm.code[vm.pc++] : 0;
}

static uint16_t fetch16(void) {
    if (!fetch_ok(2)) return 0;
    uint16_t value = (uint16_t)(vm.code[vm.pc] | (vm.code[vm.pc + 1] << 8));
    vm.pc += 2;
    return value;
}

static uint32_t fetch32(void) {
    if (!fetch_ok(4)) return 0;
    uint32_t value = read_u32(&vm.code[vm.pc]);
    vm.pc += 4;
    return value;
}

static void push(int32_t value) {
    if (vm.sp >= VM_STACK_SIZE) { trap("operand stack overflow"); return; }
    vm.stack[vm.sp++] = value;
}

static int32_t pop(void) {
    if (vm.sp == 0) { trap("operand stack underflow"); return 0; }
    return vm.stack[--vm.sp];
}

static const char* string_at(int32_t value) {
    uint32_t offset = (uint32_t)value & ACC_STRING_MASK;
    if (!((uint32_t)value & ACC_STRING_TAG) || offset >= vm.data_size) {
        trap("value is not a string");
        return "";
    }
    return (const char*)&vm.data[offset];
}

/* variables */

static int32_t* local_slot(uint16_t slot) {
    uint32_t base = vm.frame_count ? vm.frames[vm.frame_count - 1].base : 0;
    if (base + slot >= vm.locals_top) { trap("local slot outside the frame"); return &vm.locals[0]; }
    return &vm.locals[base + slot];
}

static int32_t* global_slot(uint16_t slot) {
    if (slot >= vm.global_count) { trap("global slot outside the program"); return &vm.globals[0]; }
    return &vm.globals[slot];
}

static int32_t* element(bool global, uint16_t slot, uint16_t length, int32_t index) {
    if (index < 0 || index >= length) { trap("array index out of bounds"); return &vm.globals[0]; }
    return global ? global_slot((uint16_t)(slot + index)) : local_slot((uint16_t)(slot + index));
}

static void op_adjust(bool global, bool indexed) {
    uint16_t slot = fetch16();
    uint16_t length = indexed ? fetch16() : 0;
    int8_t delta = (int8_t)fetch8();
    bool post = fetch8() != 0;
    int32_t* target = indexed ? element(global, slot, length, pop())
                              : (global ? global_slot(slot) : local_slot(slot));
    int32_t old = *target;
    *target = old + delta;
    push(post ? old : *target);
}

/* formatted output */

typedef struct {
    fs_file_handle_t* file;
    char buffer[128];
    uint32_t used;
} sink_t;

static void sink_flush(sink_t* sink) {
    if (sink->file && sink->used) filesystem_write_file(sink->file, sink->buffer, sink->used);
    sink->used = 0;
}

static void sink_put(sink_t* sink, char c) {
    if (!sink->file) {
        terminal_write_char(c);
        return;
    }
    if (sink->used == sizeof(sink->buffer)) sink_flush(sink);
    sink->buffer[sink->used++] = c;
}

static void sink_text(sink_t* sink, const char* text, uint32_t width, bool left) {
    uint32_t len = string_length(text);
    for (uint32_t i = len; !left && i < width; i++) sink_put(sink, ' ');
    for (uint32_t i = 0; i < len; i++) sink_put(sink, text[i]);
    for (uint32_t i = len; left && i < width; i++) sink_put(sink, ' ');
}

static void sink_number(sink_t* sink, uint32_t value, bool negative, uint32_t base, bool upper,
                        uint32_t width, bool left, bool zero) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char text[12];
    uint32_t n = 0;
    do { text[n++] = digits[value % base]; value /= base; } while (value);
    uint32_t len = n + (negative ? 1 : 0);
    if (negative && zero) sink_put(sink, '-');
    for (uint32_t i = len; !left && i < width; i++) sink_put(sink, zero ? '0' : ' ');
    if (negative && !zero) sink_put(sink, '-');
    while (n > 0) sink_put(sink, text[--n]);
    for (uint32_t i = len; left && i < width; i++) sink_put(sink, ' ');
}

static void format(sink_t* sink, const char* fmt, const int32_t* args, uint32_t argc) {
    uint32_t next = 0;
    for (const char* p = fmt; *p && !vm.has_error; p++) {
        if (*p != '%') { sink_put(sink, *p); continue; }
        p++;
        bool left = false, zero = false;
        while (*p == '-' || *p == '0') { if (*p == '-') left = true; else zero = true; p++; }
        uint32_t width = 0;
        while (*p >= '0' && *p <= '9') width = width * 10 + (uint32_t)(*p++ - '0');
        if (*p == '%') { sink_put(sink, '%'); continue; }
        if (next >= argc) { trap("printf has fewer arguments than conversions"); return; }
        int32_t arg = args[next++];
        switch (*p) {
            case 'd': case 'i': sink_number(sink, arg < 0 ? (uint32_t)-arg : (uint32_t)arg, arg < 0, 10, false, width, left, zero); break;
            case 'u': sink_number(sink, (uint32_t)arg, false, 10, false, width, left, zero); break;
            case 'x': case 'X': sink_number(sink, (uint32_t)arg, false, 16, *p == 'X', width, left, zero); break;
            case 'c': { char c[2] = {(char)arg, '\0'}; sink_text(sink, c, width, left); break; }
            case 's': sink_text(sink, string_at(arg), width, left); break;
            default: trap("unsupported printf conversion"); return;
        }
    }
}

/* builtins */

static fs_file_handle_t* file_at(int32_t handle) {
    int32_t index = handle - FILE_HANDLE_BASE;
    if (index < 0 || index >= VM_MAX_FILES || !vm.files[index]) { trap("invalid FILE handle"); return NULL; }
    return vm.files[index];
}

static int32_t sys_fopen(int32_t path_value, int32_t mode_value) {
    const char* path = string_at(path_value);
    const char* mode = string_at(mode_value);
    int32_t slot = -1;
    for (int32_t i = 0; i < VM_MAX_FILES; i++) if (!vm.files[i]) { slot = i; break; }
    if (slot < 0 || vm.has_error) return 0;
    bool writing = mode[0] == 'w' || mode[0] == 'a';
    if (mode[0] == 'w' && filesystem_file_exists(path)) filesystem_delete_file(path);
    if (writing && !filesystem_file_exists(path) && !filesystem_create_file(path)) return 0;
    fs_file_handle_t* handle = filesystem_open_file(path, writing);
    if (!handle) return 0;
    if (mode[0] == 'a') {
        fs_file_info_t info;
        if (filesystem_get_file_info(path, &info)) filesystem_seek_file(handle, info.size);
    }
    vm.files[slot] = handle;
    return slot + FILE_HANDLE_BASE;
}

static int32_t sys_getchar(void) {
    while (true) {
        while (!input_manager_has_input()) __asm__ volatile("pause");
        char c = input_manager_scancode_to_ascii(input_manager_read_scancode());
        if (c == '\r') return '\n';
        if (c != 0) return (uint8_t)c;
    }
}

static void sys_print(fs_file_handle_t* file, int32_t fmt, const int32_t* args, uint32_t argc) {
    sink_t sink = {file, {0}, 0};
    format(&sink, string_at(fmt), args, argc);
    sink_flush(&sink);
}

static int32_t sys_string(fs_file_handle_t* file, int32_t text, bool newline) {
    sink_t sink = {file, {0}, 0};
    sink_text(&sink, string_at(text), 0, false);
    if (newline) sink_put(&sink, '\n');
    sink_flush(&sink);
    return 0;
}

// Arguments are popped into an array so builtins see them in source order
static void op_sys(void) {
    uint8_t id = fetch8();
    uint8_t argc = fetch8();
    int32_t args[VM_FORMAT_ARGS];
    if (argc > VM_FORMAT_ARGS) { trap("too many builtin arguments"); return; }
    for (int32_t i = argc - 1; i >= 0; i--) args[i] = pop();
    if (vm.has_error) return;
    int32_t result = 0;
    switch (id) {
        case SYS_PRINTF: sys_print(NULL, args[0], args + 1, argc - 1u); break;
        case SYS_FPRINTF: { fs_file_handle_t* f = file_at(args[0]); if (f) sys_print(f, args[1], args + 2, argc - 2u); break; }
        case SYS_PUTCHAR: terminal_write_char((char)args[0]); result = args[0]; break;
        case SYS_PUTS: result = sys_string(NULL, args[0], true); break;
        case SYS_FPUTS: { fs_file_handle_t* f = file_at(args[1]); if (f) result = sys_string(f, args[0], false); break; }
        case SYS_GETCHAR: result = sys_getchar(); break;
        case SYS_EXIT: vm.exit_code = args[0]; vm.exited = true; vm.running = false; break;
        case SYS_FOPEN: result = sys_fopen(args[0], args[1]); break;
        case SYS_FCLOSE: {
            fs_file_handle_t* f = file_at(args[0]);
            if (f) { filesystem_close_file(f); vm.files[args[0] - FILE_HANDLE_BASE] = NULL; }
            break;
        }
        default: trap("unknown builtin"); return;
    }
    push(result);
}

/* calls */

static void op_call(void) {
    uint32_t address = fetch32();
    uint8_t argc = fetch8();
    if (address >= vm.code_size) { trap("call target outside the code"); return; }
    if (vm.frame_count >= VM_MAX_FRAMES) { trap("call stack overflow"); return; }
    if (vm.locals_top + argc > VM_LOCAL_SLOTS) { trap("out of local variable space"); return; }
    uint32_t base = vm.locals_top;
    for (int32_t i = argc - 1; i >= 0; i--) vm.locals[base + i] = pop();
    vm.locals_top = base + argc;
    vm.frames[vm.frame_count++] = (frame_t){vm.pc, base};
    vm.pc = address;
}

static void op_enter(void) {
    uint16_t count = fetch16();
    if (vm.frame_count == 0) { trap("ENTER outside a function"); return; }
    uint32_t base= vm.frames[vm.frame_count - 1].base;
    if (base + count > VM_LOCAL_SLOTS) { trap("out of local variable space"); return; }
    for (uint32_t i = vm.locals_top; i < base + count; i++) vm.locals[i] = 0;
    vm.locals_top = base + count;
}

static void op_ret(void) {
    int32_t value = pop();
    if (vm.frame_count == 0) { trap("return without a call"); return; }
    frame_t frame = vm.frames[--vm.frame_count];
    vm.locals_top = frame.base;
    vm.pc = frame.return_pc;
    push(value);
}

static void op_binary(uint8_t op) {
    int32_t b = pop();
    int32_t a = pop();
    int32_t r = 0;
    switch (op) {
        case OP_ADD: r = a + b; break;
        case OP_SUB: r = a - b; break;
        case OP_MUL: r = a * b; break;
        case OP_DIV: if (b == 0) { trap("division by zero"); return; } r = a / b; break;
        case OP_MOD: if (b == 0) { trap("division by zero"); return; } r = a % b; break;
        case OP_AND: r = a & b; break;
        case OP_OR: r = a | b; break;
        case OP_XOR: r = a ^ b; break;
        case OP_SHL: r = (int32_t)((uint32_t)a << (b & 31)); break;
        case OP_SHR: r = a >> (b & 31); break;
        case OP_EQ: r = a == b; break;
        case OP_NE: r = a != b; break;
        case OP_LT: r = a < b; break;
        case OP_LE: r = a <= b; break;
        case OP_GT: r = a > b; break;
        case OP_GE: r = a >= b; break;
    }
    push(r);
}

static void op_jump(uint8_t op) {
    int32_t offset = (int32_t)fetch32();
    bool take = op == OP_JMP || (op == OP_JZ ? pop() == 0 : pop() != 0);
    if (!take) return;
    int64_t target = (int64_t)vm.pc + offset;
    if (target < 0 || target >= vm.code_size) { trap("jump outside the code"); return; }
    vm.pc = (uint32_t)target;
}

static void op_variable(uint8_t op) {
    uint16_t slot = fetch16();
    switch (op) {
        case OP_LDL: push(*local_slot(slot)); break;
        case OP_LDG: push(*global_slot(slot)); break;
        case OP_STL: { int32_t v = pop(); *local_slot(slot) = v; push(v); break; }
        case OP_STG: { int32_t v = pop(); *global_slot(slot) = v; push(v); break; }
    }
}

static void op_indexed(uint8_t op) {
    uint16_t slot = fetch16();
    uint16_t length = fetch16();
    bool global = op == OP_LDGI || op == OP_STGI;
    if (op == OP_LDLI || op == OP_LDGI) {
        push(*element(global, slot, length, pop()));
        return;
    }
    int32_t value = pop();
    *element(global, slot, length, pop()) = value;
    push(value);
}

static void step(void) {
    vm.op_pc = vm.pc;
    uint8_t op = fetch8();
    switch (op) {
        case OP_HALT: vm.running = false; break;
        case OP_PUSH: push((int32_t)fetch32()); break;
        case OP_PUSHS: push((int32_t)(fetch32() | ACC_STRING_TAG)); break;
        case OP_LDL: case OP_STL: case OP_LDG: case OP_STG: op_variable(op); break;
        case OP_LDLI: case OP_STLI: case OP_LDGI: case OP_STGI: op_indexed(op); break;
        case OP_ADJL: op_adjust(false, false); break;
        case OP_ADJG: op_adjust(true, false); break;
        case OP_ADJLI: op_adjust(false, true); break;
        case OP_ADJGI: op_adjust(true, true); break;
        case OP_NEG: push(-pop()); break;
        case OP_NOT: push(!pop()); break;
        case OP_BNOT: push(~pop()); break;
        case OP_JMP: case OP_JZ: case OP_JNZ: op_jump(op); break;
        case OP_CALL: op_call(); break;
        case OP_ENTER: op_enter(); break;
        case OP_RET: op_ret(); break;
        case OP_POP: pop(); break;
        case OP_DUP: { int32_t v = pop(); push(v); push(v); break; }
        case OP_SYS: op_sys(); break;
        default:
            if (op >= OP_ADD && op <= OP_GE) op_binary(op);
            else trap("invalid opcode");
            break;
    }
}

/* loading */

void executor_initialize(void) {
    for (uint32_t i = 0; i < VM_MAX_FILES; i++) {
        if (vm.files[i]) filesystem_close_file(vm.files[i]);
        vm.files[i] = NULL;
    }
    vm.image_size = 0;
    vm.native = NULL;
    vm.sp = 0;
    vm.frame_count = 0;
    vm.locals_top = 0;
    vm.exit_code = 0;
    vm.exited = false;
    vm.has_error = false;
    vm.error[0] = '\0';
}

static bool parse_native(void) {
    const char* name = (const char*)&vm.image[NATIVE_NAME_OFFSET];
    for (uint32_t i = 0; natives[i].name; i++) {
        if (string_equals(natives[i].name, name)) {
            vm.native = &natives[i];
            return true;
        }
    }
    fail("native executable names a program that is not built into this kernel");
    return false;
}

static bool parse_header(void) {
    const uint8_t* h = vm.image;
    if (vm.image_size < ACC_HEADER_SIZE || h[0] != ACC_MAGIC_0 || h[1] != ACC_MAGIC_1 || h[2] != ACC_MAGIC_2) {
        fail("not an acc executable, the header magic is missing");
        return false;
    }
    if (h[3] == ACC_NATIVE_MAGIC_3) return parse_native();
    if (h[3] != ACC_MAGIC_3) {
        fail("unknown acc executable version");
        return false;
    }
    vm.entry = read_u32(h + 4);
    vm.code_size = read_u32(h + 8);
    vm.data_size = read_u32(h + 12);
    vm.global_count = read_u32(h + 16);
    if (ACC_HEADER_SIZE + vm.code_size + vm.data_size != vm.image_size || vm.entry >= vm.code_size ||
        vm.global_count > VM_GLOBAL_SLOTS) {
        fail("executable header does not match the file size");
        return false;
    }
    vm.code = h + ACC_HEADER_SIZE;
    vm.data = vm.code + vm.code_size;
    return true;
}

exec_result_t executor_load_file(const char* filename) {
    executor_initialize();
    fs_file_handle_t* handle = filesystem_open_file(filename, false);
    if (!handle) {
        fail("executable file not found");
        return EXEC_ERROR_FILE_NOT_FOUND;
    }
    vm.image_size = filesystem_read_file(handle, vm.image, sizeof(vm.image));
    filesystem_close_file(handle);
    return parse_header() ? EXEC_SUCCESS : EXEC_ERROR_INVALID_FILE;
}

exec_result_t executor_run(void) {
    if (vm.native) {
        vm.native->entry_point(native_data);
        vm.exit_code = 0;
        return EXEC_SUCCESS;
    }
    for (uint32_t i = 0; i < vm.global_count; i++) vm.globals[i] = 0;
    vm.pc = vm.entry;
    vm.running = true;
    uint32_t executed = 0;
    while (vm.running && !vm.has_error) {
        if (++executed > VM_INSTRUCTION_LIMIT) {
            trap("stopped after 100000000 instructions");
            break;
        }
        step();
    }
    if (!vm.has_error && !vm.exited && vm.sp > 0) vm.exit_code = vm.stack[vm.sp - 1];
    for (uint32_t i = 0; i < VM_MAX_FILES; i++) {
        if (vm.files[i]) { filesystem_close_file(vm.files[i]); vm.files[i] = NULL; }
    }
    return vm.has_error ? EXEC_ERROR_RUNTIME_ERROR : EXEC_SUCCESS;
}

exec_result_t executor_execute_file(const char* filename) {
    exec_result_t result = executor_load_file(filename);
    return result == EXEC_SUCCESS ? executor_run() : result;
}

int32_t executor_get_exit_code(void) {
    return vm.exit_code;
}

const char* executor_get_error_message(void) {
    return vm.error;
}

bool executor_write_native(const char* path, const char* program_name) {
    uint8_t image[NATIVE_NAME_OFFSET + 32];
    uint32_t len = string_length(program_name);
    if (len >= sizeof(image) - NATIVE_NAME_OFFSET) return false;
    image[0] = ACC_MAGIC_0; image[1] = ACC_MAGIC_1; image[2] = ACC_MAGIC_2; image[3] = ACC_NATIVE_MAGIC_3;
    for (uint32_t i = 0; i <= len; i++) image[NATIVE_NAME_OFFSET + i] = (uint8_t)program_name[i];
    if (!filesystem_file_exists(path) && !filesystem_create_file(path)) return false;
    fs_file_handle_t* handle = filesystem_open_file(path, true);
    if (!handle) return false;
    uint32_t size = NATIVE_NAME_OFFSET + len + 1;
    bool ok = filesystem_write_file(handle, image, size) == size;
    filesystem_close_file(handle);
    return ok;
}

/* disassembly */

typedef struct { uint8_t op; const char* name; const char* operands; } op_info_t;

static const op_info_t op_table[] = {
    {OP_HALT, "HALT", ""}, {OP_PUSH, "PUSH", "i"}, {OP_PUSHS, "PUSHS", "u"}, {OP_LDL, "LDL", "h"},
    {OP_STL, "STL", "h"}, {OP_LDG, "LDG", "h"}, {OP_STG, "STG", "h"}, {OP_LDLI, "LDLI", "hh"},
    {OP_STLI, "STLI", "hh"}, {OP_LDGI, "LDGI", "hh"}, {OP_STGI, "STGI", "hh"}, {OP_ADJL, "ADJL", "hbb"},
    {OP_ADJG, "ADJG", "hbb"}, {OP_ADJLI, "ADJLI", "hhbb"}, {OP_ADJGI, "ADJGI", "hhbb"}, {OP_ADD, "ADD", ""},
    {OP_SUB, "SUB", ""}, {OP_MUL, "MUL", ""}, {OP_DIV, "DIV", ""}, {OP_MOD, "MOD", ""}, {OP_AND, "AND", ""},
    {OP_OR, "OR", ""}, {OP_XOR, "XOR", ""}, {OP_SHL, "SHL", ""}, {OP_SHR, "SHR", ""}, {OP_EQ, "EQ", ""},
    {OP_NE, "NE", ""}, {OP_LT, "LT", ""}, {OP_LE, "LE", ""}, {OP_GT, "GT", ""}, {OP_GE, "GE", ""},
    {OP_NEG, "NEG", ""}, {OP_NOT, "NOT", ""}, {OP_BNOT, "BNOT", ""}, {OP_JMP, "JMP", "r"}, {OP_JZ, "JZ", "r"},
    {OP_JNZ, "JNZ", "r"}, {OP_CALL, "CALL", "ub"}, {OP_ENTER, "ENTER", "h"}, {OP_RET, "RET", ""},
    {OP_POP, "POP", ""}, {OP_DUP, "DUP", ""}, {OP_SYS, "SYS", "bb"}, {0xFF, NULL, NULL}
};

static void write_hex4(uint32_t value) {
    const char hex[] = "0123456789abcdef";
    for (int shift = 12; shift >= 0; shift -= 4) terminal_write_char(hex[(value >> shift) & 0xF]);
}

// Prints one instruction and returns its length, operand letters give the encoding
static uint32_t disassemble_one(uint32_t pc) {
    const op_info_t* info = NULL;
    for (uint32_t i = 0; op_table[i].name; i++) if (op_table[i].op == vm.code[pc]) info = &op_table[i];
    write_hex4(pc);
    terminal_write_string("  ");
    if (!info) {
        terminal_write_string("??\n");
        return 1;
    }
    terminal_write_string(info->name);
    uint32_t at_byte = pc + 1;
    for (const char* o = info->operands; *o && at_byte < vm.code_size; o++) {
        terminal_write_char(' ');
        if (*o == 'b') { terminal_write_int((int8_t)vm.code[at_byte]); at_byte += 1; continue; }
        if (*o == 'h') { terminal_write_uint(vm.code[at_byte] | (vm.code[at_byte + 1] << 8)); at_byte += 2; continue; }
        uint32_t value = read_u32(&vm.code[at_byte]);
        at_byte += 4;
        if (*o == 'r') write_hex4(at_byte + value);
        else if (*o == 'i') terminal_write_int((int32_t)value);
        else write_hex4(value);
    }
    terminal_write_string("\n");
    return at_byte - pc;
}

void executor_show_bytecode(const char* filename) {
    if (executor_load_file(filename) != EXEC_SUCCESS) {
        terminal_write_string("Error: ");
        terminal_write_string(vm.error);
        terminal_write_string("\n");
        return;
    }
    if (vm.native) {
        terminal_write_string("Native program built into the kernel: ");
        terminal_write_string(vm.native->name);
        terminal_write_string("\n");
        return;
    }
    terminal_write_string("Code ");
    terminal_write_uint(vm.code_size);
    terminal_write_string(" bytes, data ");
    terminal_write_uint(vm.data_size);
    terminal_write_string(" bytes, globals ");
    terminal_write_uint(vm.global_count);
    terminal_write_string(", entry ");
    write_hex4(vm.entry);
    terminal_write_string("\n");
    for (uint32_t pc = 0; pc < vm.code_size;) pc += disassemble_one(pc);
}
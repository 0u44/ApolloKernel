#include "runtime.h"

#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_EPILOG 6
#define UWOP_SPARE_CODE 7
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10
#define UNW_FLAG_NHANDLER 0
#define UNW_FLAG_EHANDLER 1
#define UNW_FLAG_UHANDLER 2
#define UNW_FLAG_CHAININFO 4
#define DISPOSITION_CONTINUE_EXECUTION 0
#define DISPOSITION_CONTINUE_SEARCH 1
#define DISPOSITION_NESTED 2
#define DISPOSITION_COLLIDED 3
#define REGISTER_RSP 4
#define FXSAVE_XMM_OFFSET 160
#define MACHINE_FRAME_RSP 24
#define NOT_IN_PROLOG 0xFFFFFFFFu
#define DOS_LFANEW 0x3C
#define OPTIONAL_HEADER_OFFSET 24
#define IMAGE_SIZE_OFFSET 56
#define DIRECTORY_EXCEPTION_OFFSET (112 + 3 * 8)
#define CONTEXT_FULL_FLAGS 0x0010000Fu
#define MAX_DISPATCH_DEPTH 16
#define ALT_STACK_SIZE (64 * 1024)
#define STACK_GUARD_SPAN (64 * 1024)
#define SIGINT 2
#define SIGILL 4
#define SIGTRAP 5
#define SIGBUS 7
#define SIGFPE 8
#define SIGSEGV 11
#define SA_SIGINFO 0x4ULL
#define SA_RESTORER 0x04000000ULL
#define SA_ONSTACK 0x08000000ULL
#define SA_NODEFER 0x40000000ULL
#define SIGSET_SIZE 8
#define FPE_INTDIV 1
#define TRAPNO_BREAKPOINT 3
#define TRAPNO_GENERAL_PROTECTION 13
#define PAGE_FAULT_WRITE 0x2
#define CTRL_C_EVENT 0
#define MAX_CTRL_HANDLERS 16
#define PROT_READ_WRITE 3
#define MAP_PRIVATE_ANONYMOUS 0x22
#define CXX_EXCEPTION 0xE06D7363u
#define STATUS_UNWIND_CONSOLIDATE 0x80000029u

typedef struct {
    DWORD begin;
    DWORD end;
    DWORD unwind;
} RUNTIME_FUNCTION;

typedef struct {
    uint64_t control_pc;
    uint64_t image_base;
    RUNTIME_FUNCTION* function;
    uint64_t establisher_frame;
    uint64_t target_ip;
    CONTEXT* context;
    void* handler;
    void* handler_data;
    void* history;
    DWORD scope_index;
    DWORD fill;
} DISPATCHER_CONTEXT;

typedef struct {
    uint8_t version_flags;
    uint8_t prolog;
    uint8_t count;
    uint8_t frame;
    uint16_t codes[];
} unwind_info_t;

typedef DWORD (WINAPI *exception_routine_t)(EXCEPTION_RECORD* record, uint64_t frame, CONTEXT* context, DISPATCHER_CONTEXT* dispatch);
typedef BOOL (WINAPI *ctrl_handler_t)(DWORD event);
typedef uint64_t (WINAPI *consolidate_t)(EXCEPTION_RECORD* record);

typedef struct {
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags;
    uint16_t cs, gs, fs, ss;
    uint64_t err, trapno, oldmask, cr2, fpstate;
    uint64_t reserved[8];
} linux_mcontext_t;

typedef struct {
    uint64_t flags;
    uint64_t link;
    uint64_t stack[3];
    linux_mcontext_t mcontext;
    uint64_t sigmask;
} linux_ucontext_t;

typedef struct {
    int32_t signo;
    int32_t error;
    int32_t code;
    int32_t pad;
    uint64_t address;
} linux_siginfo_t;

typedef struct {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
} linux_sigaction_t;

static top_filter_t top_filter;
static const CONTEXT* dispatch_origins[MAX_DISPATCH_DEPTH];
static uint32_t dispatch_depth;
static ctrl_handler_t ctrl_handlers[MAX_CTRL_HANDLERS];
static uint32_t ctrl_handler_count;
static bool ctrl_c_ignored;
static uint64_t alt_stack_low;

void rt_restore_context(const CONTEXT* context) __attribute__((noreturn));
void rt_signal_restorer(void);
extern char RaiseException[];

#define CAPTURE_ENTRY(name, target)                                   \
    ".globl " name "\n" name ":\n"                                    \
    "    sub $0x4D8, %rsp\n"                                          \
    "    mov %rax, 0x78(%rsp)\n mov %rcx, 0x80(%rsp)\n"              \
    "    mov %rdx, 0x88(%rsp)\n mov %rbx, 0x90(%rsp)\n"              \
    "    mov %rbp, 0xA0(%rsp)\n mov %rsi, 0xA8(%rsp)\n"              \
    "    mov %rdi, 0xB0(%rsp)\n mov %r8, 0xB8(%rsp)\n"               \
    "    mov %r9, 0xC0(%rsp)\n mov %r10, 0xC8(%rsp)\n"               \
    "    mov %r11, 0xD0(%rsp)\n mov %r12, 0xD8(%rsp)\n"              \
    "    mov %r13, 0xE0(%rsp)\n mov %r14, 0xE8(%rsp)\n"              \
    "    mov %r15, 0xF0(%rsp)\n"                                      \
    "    lea 0x4E0(%rsp), %rax\n mov %rax, 0x98(%rsp)\n"             \
    "    mov 0x4D8(%rsp), %rax\n mov %rax, 0xF8(%rsp)\n"             \
    "    pushfq\n pop %rax\n mov %eax, 0x44(%rsp)\n"                 \
    "    movl $0x0010000F, 0x30(%rsp)\n"                              \
    "    fxsave 0x100(%rsp)\n stmxcsr 0x34(%rsp)\n"                   \
    "    movw %cs, 0x38(%rsp)\n movw %ss, 0x42(%rsp)\n"              \
    "    mov 0x500(%rsp), %rax\n"                                     \
    "    mov %rsp, %r8\n"                                             \
    "    mov %rcx, %rdi\n mov %rdx, %rsi\n"                           \
    "    mov 0xB8(%rsp), %rdx\n mov %r9, %rcx\n mov %rax, %r9\n"      \
    "    call " target "\n"                                           \
    "    ud2\n"

__asm__(
    ".text\n"
    ".globl RtlCaptureContext\n"
    "RtlCaptureContext:\n"
    "    pushfq\n"
    "    mov %rax, 0x78(%rcx)\n mov %rcx, 0x80(%rcx)\n"
    "    mov %rdx, 0x88(%rcx)\n mov %rbx, 0x90(%rcx)\n"
    "    lea 16(%rsp), %rax\n mov %rax, 0x98(%rcx)\n"
    "    mov %rbp, 0xA0(%rcx)\n mov %rsi, 0xA8(%rcx)\n"
    "    mov %rdi, 0xB0(%rcx)\n mov %r8, 0xB8(%rcx)\n"
    "    mov %r9, 0xC0(%rcx)\n mov %r10, 0xC8(%rcx)\n"
    "    mov %r11, 0xD0(%rcx)\n mov %r12, 0xD8(%rcx)\n"
    "    mov %r13, 0xE0(%rcx)\n mov %r14, 0xE8(%rcx)\n"
    "    mov %r15, 0xF0(%rcx)\n"
    "    mov 8(%rsp), %rax\n mov %rax, 0xF8(%rcx)\n"
    "    pop %rax\n mov %eax, 0x44(%rcx)\n"
    "    movl $0x0010000F, 0x30(%rcx)\n"
    "    fxsave 0x100(%rcx)\n stmxcsr 0x34(%rcx)\n"
    "    movw %cs, 0x38(%rcx)\n movw %ss, 0x42(%rcx)\n"
    "    mov 0x78(%rcx), %rax\n"
    "    ret\n"
    ".globl rt_restore_context\n"
    "rt_restore_context:\n"
    "    fxrstor 0x100(%rdi)\n"
    "    mov 0x98(%rdi), %rax\n sub $16, %rax\n"
    "    mov 0xF8(%rdi), %rdx\n mov %rdx, 8(%rax)\n"
    "    mov 0x44(%rdi), %edx\n mov %rdx, (%rax)\n"
    "    mov 0x90(%rdi), %rbx\n mov 0xA0(%rdi), %rbp\n"
    "    mov 0xA8(%rdi), %rsi\n mov 0xB8(%rdi), %r8\n"
    "    mov 0xC0(%rdi), %r9\n mov 0xC8(%rdi), %r10\n"
    "    mov 0xD0(%rdi), %r11\n mov 0xD8(%rdi), %r12\n"
    "    mov 0xE0(%rdi), %r13\n mov 0xE8(%rdi), %r14\n"
    "    mov 0xF0(%rdi), %r15\n mov 0x80(%rdi), %rcx\n"
    "    mov 0x88(%rdi), %rdx\n"
    "    mov %rax, %rsp\n"
    "    mov 0x78(%rdi), %rax\n mov 0xB0(%rdi), %rdi\n"
    "    popfq\n"
    "    ret\n"
    ".globl rt_signal_restorer\n"
    "rt_signal_restorer:\n"
    "    mov $15, %eax\n syscall\n ud2\n"
    CAPTURE_ENTRY("RaiseException", "raise_exception")
    CAPTURE_ENTRY("RtlUnwindEx", "unwind_ex")
    CAPTURE_ENTRY("RtlUnwind", "unwind_plain"));

/* function tables */

static uint64_t image_size(uint64_t base) {
    uint32_t lfanew = *(const uint32_t*)(base + DOS_LFANEW);
    return *(const uint32_t*)(base + lfanew + OPTIONAL_HEADER_OFFSET + IMAGE_SIZE_OFFSET);
}

static bool in_runtime(uint64_t pc) {
    return pc >= WIN32_RUNTIME_BASE && pc < ((const win32_runtime_header_t*)WIN32_RUNTIME_BASE)->end;
}

WINAPI RUNTIME_FUNCTION* RtlLookupFunctionEntry(uint64_t pc, uint64_t* base, void* history) {
    (void)history;
    uint64_t image = rt_image_base();
    if (pc < image || pc >= image + image_size(image)) return NULL;
    uint32_t lfanew = *(const uint32_t*)(image + DOS_LFANEW);
    const uint32_t* dir = (const uint32_t*)(image + lfanew + OPTIONAL_HEADER_OFFSET + DIRECTORY_EXCEPTION_OFFSET);
    RUNTIME_FUNCTION* table = (RUNTIME_FUNCTION*)(image + dir[0]);
    uint32_t low = 0, high = dir[1] / sizeof(RUNTIME_FUNCTION);
    uint32_t offset = (uint32_t)(pc - image);
    while (low < high) {
        uint32_t mid = (low + high) / 2;
        if (offset < table[mid].begin) high = mid;
        else if (offset >= table[mid].end) low = mid + 1;
        else {
            *base = image;
            return &table[mid];
        }
    }
    return NULL;
}

WINAPI void* RtlPcToFileHeader(uint64_t pc, uint64_t* base) {
    uint64_t image = rt_image_base();
    if (pc >= image && pc < image + image_size(image)) *base = image;
    else if (in_runtime(pc)) *base = WIN32_RUNTIME_BASE;
    else *base = 0;
    return (void*)*base;
}

/* virtual unwinding */

static uint64_t* reg(CONTEXT* c, uint32_t n) {
    return &c->rax + n;
}

static uint8_t* xmm(CONTEXT* c, uint32_t n) {
    return c->fxsave + FXSAVE_XMM_OFFSET + n * 16;
}

static uint32_t opcode_slots(uint16_t code) {
    uint32_t op = (code >> 8) & 0xF, info = code >> 12;
    switch (op) {
        case UWOP_ALLOC_LARGE: return info ? 3 : 2;
        case UWOP_SAVE_NONVOL: case UWOP_SAVE_XMM128: case UWOP_EPILOG: return 2;
        case UWOP_SAVE_NONVOL_FAR: case UWOP_SAVE_XMM128_FAR: case UWOP_SPARE_CODE: return 3;
        default: return 1;
    }
}

static bool jump_leaves(uint64_t target, uint64_t base, const RUNTIME_FUNCTION* f) {
    return target < base + f->begin || target >= base + f->end;
}

static bool in_epilog(const uint8_t* pc, uint64_t base, const RUNTIME_FUNCTION* f) {
    if ((pc[0] & 0xF8) == 0x48) {
        if (pc[1] == 0x81 && pc[0] == 0x48 && pc[2] == 0xC4) pc += 7;
        else if (pc[1] == 0x83 && pc[0] == 0x48 && pc[2] == 0xC4) pc += 4;
        else if (pc[1] == 0x8D && !(pc[0] & 0x06) && ((pc[2] >> 3) & 7) == REGISTER_RSP && (pc[2] & 7) != REGISTER_RSP) {
            if ((pc[2] >> 6) == 1) pc += 4;
            else if ((pc[2] >> 6) == 2) pc += 7;
            else return false;
        }
    }
    for (;;) {
        if ((pc[0] & 0xF0) == 0x40) pc++;
        if (pc[0] >= 0x58 && pc[0] <= 0x5F) { pc++; continue; }
        if (pc[0] == 0xC2 || pc[0] == 0xC3) return true;
        if (pc[0] == 0xF3) return pc[1] == 0xC3;
        if (pc[0] == 0xE9) return jump_leaves((uint64_t)pc + 5 + *(const int32_t*)(pc + 1), base, f);
        if (pc[0] == 0xEB) return jump_leaves((uint64_t)pc + 2 + (int8_t)pc[1], base, f);
        if (pc[0] == 0xFF) return (pc[1] & 0x38) == 0x20;
        return false;
    }
}

static void run_epilog(const uint8_t* pc, CONTEXT* c) {
    if ((pc[0] & 0xF8) == 0x48) {
        if (pc[1] == 0x81 && pc[2] == 0xC4) { c->rsp += *(const int32_t*)(pc + 3); pc += 7; }
        else if (pc[1] == 0x83 && pc[2] == 0xC4) { c->rsp += (int8_t)pc[3]; pc += 4; }
        else if (pc[1] == 0x8D) {
            uint32_t base_reg = (pc[2] & 7) | ((pc[0] & 1) << 3);
            if ((pc[2] >> 6) == 1) { c->rsp = *reg(c, base_reg) + (int8_t)pc[3]; pc += 4; }
            else { c->rsp = *reg(c, base_reg) + *(const int32_t*)(pc + 3); pc += 7; }
        }
    }
    for (;;) {
        uint32_t extend = 0;
        if ((pc[0] & 0xF0) == 0x40) { extend = (pc[0] & 1) << 3; pc++; }
        if (pc[0] >= 0x58 && pc[0] <= 0x5F) {
            *reg(c, (pc[0] - 0x58) + extend) = *(uint64_t*)c->rsp;
            c->rsp += 8;
            pc++;
            continue;
        }
        c->rip = *(uint64_t*)c->rsp;
        c->rsp += 8;
        if (pc[0] == 0xC2) c->rsp += *(const uint16_t*)(pc + 1);
        return;
    }
}

static bool frame_register_set(const unwind_info_t* info, uint32_t prolog_offset) {
    if (!(info->frame & 0xF)) return false;
    for (uint32_t i = 0; i < info->count; i += opcode_slots(info->codes[i])) {
        if (((info->codes[i] >> 8) & 0xF) == UWOP_SET_FPREG) return prolog_offset >= (info->codes[i] & 0xFF);
    }
    return false;
}

static bool apply_codes(const unwind_info_t* info, uint32_t prolog_offset, uint64_t frame, CONTEXT* c) {
    bool machine_frame = false;
    for (uint32_t i = 0; i < info->count; i += opcode_slots(info->codes[i])) {
        uint16_t code = info->codes[i];
        uint32_t op = (code >> 8) & 0xF, n = code >> 12;
        if (prolog_offset < (uint32_t)(code & 0xFF)) continue;
        switch (op) {
            case UWOP_PUSH_NONVOL: *reg(c, n) = *(uint64_t*)c->rsp; c->rsp += 8; break;
            case UWOP_ALLOC_LARGE: c->rsp += n ? *(const uint32_t*)&info->codes[i + 1] : info->codes[i + 1] * 8u; break;
            case UWOP_ALLOC_SMALL: c->rsp += n * 8 + 8; break;
            case UWOP_SET_FPREG: c->rsp = *reg(c, info->frame & 0xF) - (info->frame >> 4) * 16u; break;
            case UWOP_SAVE_NONVOL: *reg(c, n) = *(uint64_t*)(frame + info->codes[i + 1] * 8u); break;
            case UWOP_SAVE_NONVOL_FAR: *reg(c, n) = *(uint64_t*)(frame + *(const uint32_t*)&info->codes[i + 1]); break;
            case UWOP_SAVE_XMM128: memcpy(xmm(c, n), (void*)(frame + info->codes[i + 1] * 16u), 16); break;
            case UWOP_SAVE_XMM128_FAR: memcpy(xmm(c, n), (void*)(frame + *(const uint32_t*)&info->codes[i + 1]), 16); break;
            case UWOP_PUSH_MACHFRAME:
                if (n) c->rsp += 8;
                c->rip = *(uint64_t*)c->rsp;
                c->rsp = *(uint64_t*)(c->rsp + MACHINE_FRAME_RSP);
                machine_frame = true;
                break;
            default: break;
        }
    }
    return machine_frame;
}

static const void* after_codes(const unwind_info_t* info) {
    return &info->codes[(info->count + 1) & ~1];
}

WINAPI void* RtlVirtualUnwind(DWORD type, uint64_t base, uint64_t pc, RUNTIME_FUNCTION* f, CONTEXT* c,
                              void** handler_data, uint64_t* establisher, void* pointers) {
    (void)pointers;
    if (f->unwind & 1) f = (RUNTIME_FUNCTION*)(base + (f->unwind & ~1u));
    const unwind_info_t* info = (const unwind_info_t*)(base + f->unwind);
    uint32_t offset = (uint32_t)(pc - base - f->begin);
    uint32_t prolog_offset = offset < info->prolog ? offset : NOT_IN_PROLOG;
    uint64_t frame = frame_register_set(info, prolog_offset) ? *reg(c, info->frame & 0xF) - (info->frame >> 4) * 16u : c->rsp;
    *establisher = frame;
    if (prolog_offset == NOT_IN_PROLOG && in_epilog((const uint8_t*)pc, base, f)) {
        run_epilog((const uint8_t*)pc, c);
        return NULL;
    }
    void* handler = NULL;
    if (prolog_offset == NOT_IN_PROLOG && ((info->version_flags >> 3) & type)) {
        handler = (void*)(base + *(const uint32_t*)after_codes(info));
        *handler_data = (uint8_t*)after_codes(info) + sizeof(uint32_t);
    }
    bool machine_frame = apply_codes(info, prolog_offset, frame, c);
    while ((info->version_flags >> 3) & UNW_FLAG_CHAININFO) {
        const RUNTIME_FUNCTION* chained = after_codes(info);
        info = (const unwind_info_t*)(base + chained->unwind);
        machine_frame |= apply_codes(info, NOT_IN_PROLOG, frame, c);
    }
    if (!machine_frame) {
        c->rip = *(uint64_t*)c->rsp;
        c->rsp += 8;
    }
    return handler;
}

static bool valid_frame(uint64_t frame) {
    bool main_stack = frame >= rt_stack_limit() && frame < rt_stack_base();
    bool alt_stack = alt_stack_low && frame >= alt_stack_low && frame < alt_stack_low + ALT_STACK_SIZE;
    return (main_stack || alt_stack) && frame % 8 == 0;
}

static bool cross_runtime(CONTEXT* c, uint32_t floor) {
    if (!in_runtime(c->rip) || dispatch_depth <= floor || dispatch_depth == 0) return false;
    *c = *dispatch_origins[--dispatch_depth];
    return true;
}

typedef struct {
    RUNTIME_FUNCTION* function;
    uint64_t base;
    void* handler;
    void* data;
    uint64_t frame;
} step_t;

static bool step_frame(DWORD type, uint32_t floor, CONTEXT* current, CONTEXT* next, step_t* s) {
    while (cross_runtime(current, floor)) {}
    *next = *current;
    s->handler = NULL;
    s->function = RtlLookupFunctionEntry(current->rip, &s->base, NULL);
    if (s->function) {
        s->handler = RtlVirtualUnwind(type, s->base, current->rip, s->function, next, &s->data, &s->frame, NULL);
    } else {
        if (in_runtime(current->rip) || !valid_frame(current->rsp)) return false;
        s->frame = current->rsp;
        next->rip = *(uint64_t*)current->rsp;
        next->rsp += 8;
    }
    return valid_frame(s->frame) && next->rip != 0;
}

static bool dispatch_exception(EXCEPTION_RECORD* record, CONTEXT* original) {
    CONTEXT current = *original, next;
    step_t s;
    uint32_t depth = dispatch_depth;
    if (dispatch_depth < MAX_DISPATCH_DEPTH) dispatch_origins[dispatch_depth++] = original;
    bool handled = false;
    uint32_t floor = dispatch_depth;
    while (step_frame(UNW_FLAG_EHANDLER, floor, &current, &next, &s)) {
        if (s.handler) {
            DISPATCHER_CONTEXT dispatch = {current.rip, s.base, s.function, s.frame, 0, &current, s.handler, s.data, NULL, 0, 0};
            DWORD result = ((exception_routine_t)s.handler)(record, s.frame, original, &dispatch);
            if (result == DISPOSITION_CONTINUE_EXECUTION) {
                if (record->flags & EXCEPTION_NONCONTINUABLE) rt_raise_status(STATUS_NONCONTINUABLE_EXCEPTION);
                handled = true;
                break;
            }
            if (result != DISPOSITION_CONTINUE_SEARCH && result != DISPOSITION_NESTED) rt_raise_status(STATUS_INVALID_DISPOSITION);
        }
        current = next;
    }
    dispatch_depth = depth;
    return handled;
}

static void call_unwind_handler(EXCEPTION_RECORD* record, DISPATCHER_CONTEXT* dispatch, CONTEXT* next, uint64_t* frame) {
    DWORD result = ((exception_routine_t)dispatch->handler)(record, dispatch->establisher_frame, dispatch->context, dispatch);
    record->flags &= ~(DWORD)(EXCEPTION_COLLIDED_UNWIND | EXCEPTION_TARGET_UNWIND);
    if (result == DISPOSITION_COLLIDED) {
        *next = *dispatch->context;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, dispatch->image_base, dispatch->control_pc, dispatch->function,
                         next, &dispatch->handler_data, frame, NULL);
        record->flags |= EXCEPTION_COLLIDED_UNWIND;
    } else if (result != DISPOSITION_CONTINUE_SEARCH) {
        rt_raise_status(STATUS_INVALID_DISPOSITION);
    }
}

static uint64_t consolidate(EXCEPTION_RECORD* record, const CONTEXT* target) {
    uint32_t depth = dispatch_depth;
    if (dispatch_depth < MAX_DISPATCH_DEPTH) dispatch_origins[dispatch_depth++] = target;
    uint64_t resume = ((consolidate_t)record->information[0])(record);
    dispatch_depth = depth;
    return resume;
}

static void do_unwind(uint64_t target_frame, uint64_t target_ip, EXCEPTION_RECORD* record, uint64_t value, CONTEXT* context) {
    EXCEPTION_RECORD local = {STATUS_UNWIND, EXCEPTION_UNWINDING, NULL, (void*)context->rip, 0, {0}};
    if (!record) record = &local;
    record->flags |= EXCEPTION_UNWINDING | (target_frame ? 0 : EXCEPTION_EXIT_UNWIND);
    CONTEXT next;
    step_t s;
    for (;;) {
        if (!step_frame(UNW_FLAG_UHANDLER, 0, context, &next, &s)) rt_raise_status(STATUS_BAD_STACK);
        if (target_frame && s.frame > target_frame) rt_raise_status(STATUS_INVALID_UNWIND_TARGET);
        if (s.handler) {
            DISPATCHER_CONTEXT dispatch = {context->rip, s.base, s.function, s.frame, target_ip, context, s.handler, s.data, NULL, 0, 0};
            if (s.frame == target_frame) record->flags |= EXCEPTION_TARGET_UNWIND;
            call_unwind_handler(record, &dispatch, &next, &s.frame);
        }
        if (s.frame == target_frame) break;
        *context = next;
    }
    context->rax = value;
    context->rip = target_ip;
    if (record->code == STATUS_UNWIND_CONSOLIDATE && record->parameter_count >= 1) context->rip = consolidate(record, context);
    rt_restore_context(context);
}

__attribute__((used, noreturn)) void unwind_ex(uint64_t target_frame, uint64_t target_ip, EXCEPTION_RECORD* record,
                                                uint64_t value, CONTEXT* captured) {
    do_unwind(target_frame, target_ip, record, value, captured);
    __builtin_unreachable();
}

__attribute__((used, noreturn)) void unwind_plain(uint64_t target_frame, uint64_t target_ip, EXCEPTION_RECORD* record,
                                                   uint64_t value, CONTEXT* captured) {
    do_unwind(target_frame, target_ip, record, value, captured);
    __builtin_unreachable();
}

static const char* status_name(DWORD code) {
    switch (code) {
        case STATUS_ACCESS_VIOLATION: return "access violation";
        case STATUS_INTEGER_DIVIDE_BY_ZERO: return "integer divide by zero";
        case STATUS_ILLEGAL_INSTRUCTION: return "illegal instruction";
        case STATUS_BREAKPOINT: return "breakpoint";
        case STATUS_STACK_OVERFLOW: return "stack overflow";
        case STATUS_DATATYPE_MISALIGNMENT: return "misaligned data";
        case STATUS_FLOAT_INVALID_OPERATION: return "floating point invalid operation";
        case STATUS_NO_MEMORY: return "out of memory";
        case CXX_EXCEPTION: return "C++ exception";
        default: return "exception";
    }
}

static void report(const EXCEPTION_RECORD* record) {
    rt_write_text("\nUnhandled exception 0x");
    rt_write_hex(record->code, 8);
    rt_write_text(" (");
    rt_write_text(status_name(record->code));
    rt_write_text(") at 0x");
    rt_write_hex((uint64_t)record->address, 16);
    if (record->code == STATUS_ACCESS_VIOLATION && record->parameter_count >= 2) {
        rt_write_text(record->information[0] ? ", writing 0x" : ", reading 0x");
        rt_write_hex(record->information[1], 16);
    }
    rt_write_text("\n");
}

WINAPI top_filter_t SetUnhandledExceptionFilter(top_filter_t filter) {
    top_filter_t previous = top_filter;
    top_filter = filter;
    return previous;
}

WINAPI LONG UnhandledExceptionFilter(EXCEPTION_POINTERS* pointers) {
    if (top_filter) {
        LONG r = top_filter(pointers);
        if (r != EXCEPTION_CONTINUE_SEARCH) return r;
    }
    report(pointers->record);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void handle_exception(EXCEPTION_RECORD* record, CONTEXT* context) {
    if (dispatch_exception(record, context)) return;
    EXCEPTION_POINTERS pointers = {record, context};
    if (UnhandledExceptionFilter(&pointers) == EXCEPTION_CONTINUE_EXECUTION) return;
    rt_exit(record->code);
}

__attribute__((used, noreturn)) void raise_exception(DWORD code, DWORD flags, DWORD count, const ULONG_PTR* arguments, CONTEXT* captured) {
    EXCEPTION_RECORD record;
    memset(&record, 0, sizeof(record));
    record.code = code;
    record.flags = flags & EXCEPTION_NONCONTINUABLE;
    record.address = (void*)captured->rip;
    record.parameter_count = count < EXCEPTION_MAXIMUM_PARAMETERS ? count : EXCEPTION_MAXIMUM_PARAMETERS;
    for (DWORD i = 0; arguments && i < record.parameter_count; i++) record.information[i] = arguments[i];
    handle_exception(&record, captured);
    rt_restore_context(captured);
}

void rt_raise_status(DWORD code) {
    ULONG_PTR none = 0;
    ((void (WINAPI *)(DWORD, DWORD, DWORD, const ULONG_PTR*))RaiseException)(code, EXCEPTION_NONCONTINUABLE, 0, &none);
    rt_exit(code);
}

void rt_fatal(const char* message, DWORD code) {
    rt_write_text("\n");
    rt_write_text(message);
    rt_write_text("\n");
    rt_exit(code);
}

static void context_from_signal(CONTEXT* c, const linux_ucontext_t* uc) {
    const linux_mcontext_t* m = &uc->mcontext;
    memset(c, 0, sizeof(*c));
    c->context_flags = CONTEXT_FULL_FLAGS;
    c->rax = m->rax; c->rcx = m->rcx; c->rdx = m->rdx; c->rbx = m->rbx;
    c->rsp = m->rsp; c->rbp = m->rbp; c->rsi = m->rsi; c->rdi = m->rdi;
    c->r8 = m->r8; c->r9 = m->r9; c->r10 = m->r10; c->r11 = m->r11;
    c->r12 = m->r12; c->r13 = m->r13; c->r14 = m->r14; c->r15 = m->r15;
    c->rip = m->rip;
    c->eflags = (DWORD)m->eflags;
    c->seg_cs = m->cs;
    c->seg_ss = m->ss;
    if (m->fpstate) memcpy(c->fxsave, (const void*)m->fpstate, sizeof(c->fxsave));
    c->mxcsr = *(const DWORD*)(c->fxsave + 24);
}

static void context_to_signal(const CONTEXT* c, linux_ucontext_t* uc) {
    linux_mcontext_t* m = &uc->mcontext;
    m->rax = c->rax; m->rcx = c->rcx; m->rdx = c->rdx; m->rbx = c->rbx;
    m->rsp = c->rsp; m->rbp = c->rbp; m->rsi = c->rsi; m->rdi = c->rdi;
    m->r8 = c->r8; m->r9 = c->r9; m->r10 = c->r10; m->r11 = c->r11;
    m->r12 = c->r12; m->r13 = c->r13; m->r14 = c->r14; m->r15 = c->r15;
    m->rip = c->rip;
    m->eflags = c->eflags;
    if (m->fpstate) memcpy((void*)m->fpstate, c->fxsave, sizeof(c->fxsave));
}

static void record_from_signal(EXCEPTION_RECORD* r, int signal, const linux_siginfo_t* info, const linux_ucontext_t* uc, CONTEXT* c) {
    memset(r, 0, sizeof(*r));
    r->address = (void*)c->rip;
    switch (signal) {
        case SIGFPE: r->code = info->code == FPE_INTDIV ? STATUS_INTEGER_DIVIDE_BY_ZERO : STATUS_FLOAT_INVALID_OPERATION; return;
        case SIGILL: r->code = STATUS_ILLEGAL_INSTRUCTION; return;
        case SIGBUS: r->code = STATUS_DATATYPE_MISALIGNMENT; return;
        case SIGTRAP:
            if (uc->mcontext.trapno == TRAPNO_BREAKPOINT) c->rip--;
            r->address = (void*)c->rip;
            r->code = STATUS_BREAKPOINT;
            return;
        default: break;
    }
    bool overflow = info->address < rt_stack_limit() && info->address >= rt_stack_limit() - STACK_GUARD_SPAN;
    r->code = overflow ? STATUS_STACK_OVERFLOW : STATUS_ACCESS_VIOLATION;
    r->parameter_count = 2;
    r->information[0] = (uc->mcontext.err & PAGE_FAULT_WRITE) ? 1 : 0;
    r->information[1] = uc->mcontext.trapno == TRAPNO_GENERAL_PROTECTION ? ~0ULL : info->address;
}

static void fault_handler(int signal, linux_siginfo_t* info, linux_ucontext_t* uc) {
    CONTEXT context;
    EXCEPTION_RECORD record;
    context_from_signal(&context, uc);
    record_from_signal(&record, signal, info, uc, &context);
    handle_exception(&record, &context);
    context_to_signal(&context, uc);
}

static void interrupt_handler(int signal, linux_siginfo_t* info, linux_ucontext_t* uc) {
    (void)signal; (void)info; (void)uc;
    if (ctrl_c_ignored) return;
    for (uint32_t i = ctrl_handler_count; i > 0; i--) {
        if (ctrl_handlers[i - 1](CTRL_C_EVENT)) return;
    }
    rt_write_text("^C\n");
    rt_exit(STATUS_CONTROL_C_EXIT);
}

WINAPI BOOL SetConsoleCtrlHandler(ctrl_handler_t handler, BOOL add) {
    if (!handler) {
        ctrl_c_ignored = add;
        return TRUE;
    }
    if (add) {
        if (ctrl_handler_count >= MAX_CTRL_HANDLERS) {
            rt_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        ctrl_handlers[ctrl_handler_count++] = handler;
        return TRUE;
    }
    for (uint32_t i = 0; i < ctrl_handler_count; i++) {
        if (ctrl_handlers[i] != handler) continue;
        ctrl_handlers[i] = ctrl_handlers[--ctrl_handler_count];
        return TRUE;
    }
    rt_set_last_error(ERROR_INVALID_PARAMETER);
    return FALSE;
}

static void install(int signal, void (*handler)(int, linux_siginfo_t*, linux_ucontext_t*)) {
    linux_sigaction_t action = {(uint64_t)handler, SA_SIGINFO | SA_RESTORER | SA_ONSTACK | SA_NODEFER, (uint64_t)rt_signal_restorer, 0};
    sys4(LINUX_RT_SIGACTION, signal, &action, 0, SIGSET_SIZE);
}

void rt_exceptions_initialize(void) {
    int64_t stack = sys6(LINUX_MMAP, 0, ALT_STACK_SIZE, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, (uint64_t)-1, 0);
    if (stack > 0) {
        uint64_t descriptor[3] = {(uint64_t)stack, 0, ALT_STACK_SIZE};
        if (sys2(LINUX_SIGALTSTACK, descriptor, 0) == 0) alt_stack_low = (uint64_t)stack;
    }
    install(SIGSEGV, fault_handler);
    install(SIGILL, fault_handler);
    install(SIGFPE, fault_handler);
    install(SIGBUS, fault_handler);
    install(SIGTRAP, fault_handler);
    install(SIGINT, interrupt_handler);
}
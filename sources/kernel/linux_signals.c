#include "linux_abi.h"
#include "terminal.h"

#define SIG_DFL 0
#define SIG_IGN 1
#define SA_RESTORER 0x04000000ULL
#define SA_ONSTACK 0x08000000ULL
#define SA_RESTART 0x10000000ULL
#define SA_NODEFER 0x40000000ULL
#define SA_RESETHAND 0x80000000ULL
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
#define SS_ONSTACK 1
#define SS_DISABLE 2
#define MIN_SIGNAL_STACK 2048
#define SIGCHLD 17
#define SIGCONT 18
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGWINCH 28
#define RED_ZONE 128
#define FXSAVE_SIZE 512
#define FXSAVE_ALIGN 64
#define STACK_ALIGN 16
#define SYSCALL_INSTRUCTION_LENGTH 2
#define SIGSET_SIZE 8
#define EXIT_SIGNAL_BASE 128
#define SI_KERNEL 0x80
#define SI_TKILL (-6)
#define FPE_INTDIV 1
#define FPE_FLTINV 7
#define SEGV_MAPERR 1
#define SEGV_ACCERR 2
#define ILL_ILLOPN 2
#define TRAP_BRKPT 1
#define BUS_ADRALN 1
#define PAGE_FAULT_PRESENT 1
#define USER_RFLAGS_MASK 0x40DD5ULL
#define NO_CALL ((uint64_t)-1)
#define FXSAVE_MXCSR_OFFSET 24
#define FXSAVE_MXCSR_MASK_OFFSET 28
// What the CPU reports when the mask field is zero
#define MXCSR_DEFAULT_MASK 0xFFBFu

typedef struct {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
} linux_sigaction_t;

typedef struct {
    uint64_t sp;
    int32_t flags;
    int32_t pad;
    uint64_t size;
} linux_stack_t;

// Field order is the kernel's struct sigcontext
typedef struct {
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags;
    uint16_t cs, gs, fs, ss;
    uint64_t err, trapno, oldmask, cr2, fpstate;
    uint64_t reserved[8];
} linux_sigcontext_t;

typedef struct {
    uint64_t flags;
    uint64_t link;
    linux_stack_t stack;
    linux_sigcontext_t mcontext;
    uint64_t sigmask;
} linux_ucontext_t;

typedef struct {
    int32_t signo;
    int32_t error;
    int32_t code;
    int32_t pad;
    uint64_t address;
    uint8_t rest[104];
} linux_siginfo_t;

static linux_sigaction_t actions[LINUX_SIGNALS + 1];
static uint64_t blocked;
static uint64_t pending;
static linux_stack_t altstack;
static uint8_t fx_buffer[FXSAVE_SIZE] ALIGNED(FXSAVE_ALIGN);
static uint32_t mxcsr_mask;

static const char* const termination_names[] = {
    [SIGINT] = "Interrupted", [SIGABRT] = "Aborted", [SIGKILL] = "Killed", [SIGTERM] = "Terminated",
    [SIGPIPE] = "Broken pipe", [SIGSEGV] = "Segmentation fault", [SIGBUS] = "Bus error",
    [SIGFPE] = "Floating point exception", [SIGILL] = "Illegal instruction", [SIGTRAP] = "Trace trap",
};

static inline uint64_t bit(int signal) {
    return 1ULL << (signal - 1);
}

static const uint64_t unblockable = (1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1));

void linux_signals_reset(void) {
    memset(actions, 0, sizeof(actions));
    blocked = pending = 0;
    altstack = (linux_stack_t){0, SS_DISABLE, 0, 0};
    // Reserved MXCSR bits make fxrstor fault in the kernel, so restored state is masked with what the CPU allows
    __asm__ volatile("fxsave64 (%0)" : : "r"(fx_buffer) : "memory");
    mxcsr_mask = *(uint32_t*)(fx_buffer + FXSAVE_MXCSR_MASK_OFFSET);
    if (mxcsr_mask == 0) mxcsr_mask = MXCSR_DEFAULT_MASK;
}

/* system calls */

int64_t linux_rt_sigaction(interrupt_frame_t* f) {
    int signal = (int)ARG0(f);
    if (signal < 1 || signal > LINUX_SIGNALS || ARG3(f) != SIGSET_SIZE) return -EINVAL;
    if (ARG2(f) && !user_copy_out(ARG2(f), &actions[signal], sizeof(linux_sigaction_t))) return -EFAULT;
    if (!ARG1(f)) return 0;
    if (signal == SIGKILL || signal == SIGSTOP) return -EINVAL;
    linux_sigaction_t action;
    if (!user_copy_in(&action, ARG1(f), sizeof(action))) return -EFAULT;
    action.mask &= ~unblockable;
    actions[signal] = action;
    return 0;
}

int64_t linux_rt_sigprocmask(interrupt_frame_t* f) {
    if (ARG3(f) != SIGSET_SIZE) return -EINVAL;
    uint64_t old = blocked;
    if (ARG1(f)) {
        uint64_t set;
        if (!user_copy_in(&set, ARG1(f), sizeof(set))) return -EFAULT;
        if (ARG0(f) == SIG_BLOCK) blocked |= set;
        else if (ARG0(f) == SIG_UNBLOCK) blocked &= ~set;
        else if (ARG0(f) == SIG_SETMASK) blocked = set;
        else return -EINVAL;
        blocked &= ~unblockable;
    }
    if (ARG2(f) && !user_copy_out(ARG2(f), &old, sizeof(old))) return -EFAULT;
    return 0;
}

static bool on_altstack(uint64_t sp) {
    return !(altstack.flags & SS_DISABLE) && sp > altstack.sp && sp <= altstack.sp + altstack.size;
}

int64_t linux_sigaltstack(interrupt_frame_t* f) {
    linux_stack_t old = altstack;
    if (on_altstack(f->rsp)) old.flags |= SS_ONSTACK;
    if (ARG0(f)) {
        linux_stack_t next;
        if (!user_copy_in(&next, ARG0(f), sizeof(next))) return -EFAULT;
        if (on_altstack(f->rsp)) return -EPERM;
        if (next.flags & ~SS_DISABLE) return -EINVAL;
        if (!(next.flags & SS_DISABLE) && next.size < MIN_SIGNAL_STACK) return -ENOMEM;
        altstack = next;
    }
    if (ARG1(f) && !user_copy_out(ARG1(f), &old, sizeof(old))) return -EFAULT;
    return 0;
}

static int64_t raise_signal(int signal) {
    if (signal < 0 || signal > LINUX_SIGNALS) return -EINVAL;
    if (signal > 0) pending |= bit(signal);
    return 0;
}

int64_t linux_kill(interrupt_frame_t* f) {
    int64_t pid = (int64_t)ARG0(f);
    if (pid != program.pid && pid != 0 && pid != -1) return -ESRCH;
    return raise_signal((int)ARG1(f));
}

int64_t linux_tgkill(interrupt_frame_t* f) {
    if ((int64_t)ARG1(f) != program.pid) return -ESRCH;
    return raise_signal((int)ARG2(f));
}

bool linux_signal_waiting(void) {
    return (pending & ~blocked) != 0;
}

bool linux_queue_signal_interrupt(void) {
    if (actions[SIGINT].handler == SIG_DFL) return false;
    if (actions[SIGINT].handler != SIG_IGN) pending |= bit(SIGINT);
    return true;
}

/* delivery */

static bool ignored_by_default(int signal) {
    return signal == SIGCHLD || signal == SIGURG || signal == SIGWINCH || signal == SIGCONT ||
           signal == SIGTSTP || signal == SIGTTIN || signal == SIGTTOU;
}

static void terminate(int signal) {
    const char* name = (uint32_t)signal < ARRAY_SIZE(termination_names) ? termination_names[signal] : NULL;
    terminal_set_color(12, 0);
    terminal_write_string("\n");
    if (name) {
        terminal_write_string(name);
    } else {
        terminal_write_string("Terminated by signal ");
        terminal_write_uint((uint32_t)signal);
    }
    terminal_write_string("\n");
    terminal_set_color(7, 0);
    program_exit(EXIT_SIGNAL_BASE + signal);
}

static void save_context(linux_sigcontext_t* c, const interrupt_frame_t* f, uint64_t fpstate) {
    memset(c, 0, sizeof(*c));
    c->r8 = f->r8; c->r9 = f->r9; c->r10 = f->r10; c->r11 = f->r11;
    c->r12 = f->r12; c->r13 = f->r13; c->r14 = f->r14; c->r15 = f->r15;
    c->rdi = f->rdi; c->rsi = f->rsi; c->rbp = f->rbp; c->rbx = f->rbx;
    c->rdx = f->rdx; c->rax = f->rax; c->rcx = f->rcx; c->rsp = f->rsp;
    c->rip = f->rip; c->eflags = f->rflags;
    c->cs = USER_CODE_SELECTOR;
    c->ss = USER_DATA_SELECTOR;
    c->trapno = f->vector;
    c->err = f->error_code;
    c->cr2 = f->vector == EXCEPTION_PAGE_FAULT ? cpu_read_cr2() : 0;
    c->oldmask = blocked;
    c->fpstate = fpstate;
}

// Builds the kernel's rt_sigframe on the user stack and points the program at the handler
static bool start_handler(interrupt_frame_t* f, int signal, const linux_siginfo_t* info) {
    linux_sigaction_t* action = &actions[signal];
    uint64_t sp = f->rsp;
    if ((action->flags & SA_ONSTACK) && !(altstack.flags & SS_DISABLE) && !on_altstack(sp)) sp = altstack.sp + altstack.size;
    uint64_t fp = ALIGN_DOWN(sp - RED_ZONE - FXSAVE_SIZE, FXSAVE_ALIGN);
    uint64_t info_at = fp - sizeof(linux_siginfo_t);
    uint64_t uc_at = ALIGN_DOWN(info_at - sizeof(linux_ucontext_t), STACK_ALIGN);
    uint64_t frame_at = uc_at - sizeof(uint64_t);
    if (!user_check(frame_at, sp - frame_at, true)) return false;
    linux_ucontext_t uc;
    memset(&uc, 0, sizeof(uc));
    uc.stack = altstack;
    save_context(&uc.mcontext, f, fp);
    uc.sigmask = blocked;
    __asm__ volatile("fxsave64 (%0)" : : "r"(fp) : "memory");
    uint64_t restorer = (action->flags & SA_RESTORER) ? action->restorer : 0;
    user_copy_out(info_at, info, sizeof(*info));
    user_copy_out(uc_at, &uc, sizeof(uc));
    user_copy_out(frame_at, &restorer, sizeof(restorer));
    f->rsp = frame_at;
    f->rip = action->handler;
    f->rdi = (uint64_t)signal;
    f->rsi = info_at;
    f->rdx = uc_at;
    f->rax = 0;
    f->rflags &= ~(1ULL << 10);
    blocked |= action->mask | ((action->flags & SA_NODEFER) ? 0 : bit(signal));
    blocked &= ~unblockable;
    if (action->flags & SA_RESETHAND) action->handler = SIG_DFL;
    return true;
}

static int next_deliverable(void) {
    uint64_t ready = pending & ~blocked;
    if (!ready) return 0;
    return __builtin_ctzll(ready) + 1;
}

// A blocked read that was interrupted restarts when no handler runs or the handler asked for SA_RESTART
static void settle_interrupted_call(interrupt_frame_t* f, uint64_t call, int64_t result, bool handler_runs, int signal) {
    if (call == NO_CALL || result != -ERESTARTSYS) return;
    if (!handler_runs || (actions[signal].flags & SA_RESTART)) {
        f->rax = call;
        f->rip -= SYSCALL_INSTRUCTION_LENGTH;
    } else {
        f->rax = (uint64_t)-EINTR;
    }
}

void linux_deliver_pending(interrupt_frame_t* f, uint64_t call, int64_t result) {
    int signal = next_deliverable();
    if (!signal) {
        settle_interrupted_call(f, call, result, false, 0);
        return;
    }
    pending &= ~bit(signal);
    uint64_t handler = actions[signal].handler;
    if (handler == SIG_IGN || (handler == SIG_DFL && ignored_by_default(signal))) {
        settle_interrupted_call(f, call, result, false, signal);
        return;
    }
    if (handler == SIG_DFL) terminate(signal);
    settle_interrupted_call(f, call, result, true, signal);
    linux_siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.signo = signal;
    info.code = SI_TKILL;
    if (!start_handler(f, signal, &info)) terminate(SIGSEGV);
}

void linux_after_trap(interrupt_frame_t* frame) {
    linux_deliver_pending(frame, NO_CALL, 0);
}

static int32_t fault_code(const interrupt_frame_t* frame, int signal) {
    switch (signal) {
        case SIGFPE: return frame->vector == EXCEPTION_DIVIDE ? FPE_INTDIV : FPE_FLTINV;
        case SIGSEGV: return (frame->error_code & PAGE_FAULT_PRESENT) ? SEGV_ACCERR : SEGV_MAPERR;
        case SIGILL: return ILL_ILLOPN;
        case SIGTRAP: return TRAP_BRKPT;
        default: return BUS_ADRALN;
    }
}

bool linux_deliver_fault(interrupt_frame_t* frame, int signal) {
    uint64_t handler = actions[signal].handler;
    if (handler == SIG_DFL || handler == SIG_IGN || (blocked & bit(signal))) return false;
    linux_siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.signo = signal;
    info.code = fault_code(frame, signal);
    info.address = frame->vector == EXCEPTION_PAGE_FAULT ? cpu_read_cr2() : frame->rip;
    return start_handler(frame, signal, &info);
}

int64_t linux_rt_sigreturn(interrupt_frame_t* f) {
    linux_ucontext_t uc;
    if (!user_copy_in(&uc, f->rsp, sizeof(uc))) terminate(SIGSEGV);
    const linux_sigcontext_t* c = &uc.mcontext;
    f->r8 = c->r8; f->r9 = c->r9; f->r10 = c->r10; f->r11 = c->r11;
    f->r12 = c->r12; f->r13 = c->r13; f->r14 = c->r14; f->r15 = c->r15;
    f->rdi = c->rdi; f->rsi = c->rsi; f->rbp = c->rbp; f->rbx = c->rbx;
    f->rdx = c->rdx; f->rcx = c->rcx; f->rsp = c->rsp; f->rip = c->rip;
    f->rflags = (c->eflags & USER_RFLAGS_MASK) | RFLAGS_IF | RFLAGS_RESERVED;
    f->cs = USER_CODE_SELECTOR;
    f->ss = USER_DATA_SELECTOR;
    if (c->fpstate && user_copy_in(fx_buffer, c->fpstate, FXSAVE_SIZE)) {
        *(uint32_t*)(fx_buffer + FXSAVE_MXCSR_OFFSET) &= mxcsr_mask;
        __asm__ volatile("fxrstor64 (%0)" : : "r"(fx_buffer) : "memory");
    }
    blocked = uc.sigmask & ~unblockable;
    return (int64_t)c->rax;
}
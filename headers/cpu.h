#ifndef APOLLO_CPU_H
#define APOLLO_CPU_H

#include "types.h"

#define KERNEL_CODE_SELECTOR 0x08
#define KERNEL_DATA_SELECTOR 0x10
#define USER_DATA_SELECTOR 0x1B
#define USER_CODE_SELECTOR 0x23
#define TSS_SELECTOR 0x28

#define EXCEPTION_COUNT 32
#define IRQ_BASE_VECTOR 32
#define IRQ_TIMER_VECTOR 32
#define IRQ_SPURIOUS_VECTOR 39
#define SYSCALL_VECTOR 0x100
#define VECTOR_COUNT 257
#define TIMER_HZ 100

#define EXCEPTION_DIVIDE 0
#define EXCEPTION_DEBUG 1
#define EXCEPTION_BREAKPOINT 3
#define EXCEPTION_INVALID_OPCODE 6
#define EXCEPTION_DOUBLE_FAULT 8
#define EXCEPTION_GENERAL_PROTECTION 13
#define EXCEPTION_PAGE_FAULT 14
#define EXCEPTION_X87 16
#define EXCEPTION_ALIGNMENT 17
#define EXCEPTION_SIMD 19

#define RFLAGS_IF (1ULL << 9)
#define RFLAGS_RESERVED (1ULL << 1)

// Layout matches the pushes in interrupts.s, the syscall entry builds the same frame
typedef struct {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t vector, error_code;
    uint64_t rip, cs, rflags, rsp, ss;
} interrupt_frame_t;

typedef void (*interrupt_handler_t)(interrupt_frame_t* frame);

void cpu_initialize(void);
void cpu_set_handler(uint32_t vector, interrupt_handler_t handler);
const char* cpu_exception_name(uint64_t vector);
uint64_t cpu_read_cr2(void);
uint64_t cpu_read_cr3(void);
void cpu_write_cr3(uint64_t value);
uint64_t cpu_kernel_cr3(void);
void cpu_set_fs_base(uint64_t base);
void cpu_set_gs_base(uint64_t base);
void cpu_timer_enable(bool enable);
uint64_t cpu_timer_ticks(void);

interrupt_frame_t* cpu_user_frame(void);
uint64_t cpu_enter_user(interrupt_frame_t* frame);
void cpu_leave_user(uint64_t result) __attribute__((noreturn));

#endif
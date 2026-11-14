global interrupt_stub_table
global syscall_entry
global interrupt_return
global cpu_enter_user
global cpu_leave_user
global syscall_kernel_rsp
extern interrupt_dispatch

SYSCALL_VECTOR equ 0x100
USER_DATA_SELECTOR equ 0x1B
USER_CODE_SELECTOR equ 0x23
EXCEPTION_COUNT equ 32
STUB_COUNT equ 48

section .text
bits 64

%macro SAVE_REGISTERS 0
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro RESTORE_REGISTERS 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Vectors 8, 10 to 14, 17, 21, 29 and 30 push an error code, the rest get a zero so the frame is uniform
%macro STUB 1
interrupt_stub_%1:
%if %1 = 8 || (%1 >= 10 && %1 <= 14) || %1 = 17 || %1 = 21 || %1 = 29 || %1 = 30
%else
    push 0
%endif
    push %1
    jmp interrupt_common
%endmacro

%assign i 0
%rep STUB_COUNT
STUB i
%assign i i + 1
%endrep

interrupt_common:
    SAVE_REGISTERS
    mov rdi, rsp
    call interrupt_dispatch
interrupt_return:
    RESTORE_REGISTERS
    add rsp, 16
    iretq

; syscall leaves the user stack in place, so switch to the kernel stack before building the frame
syscall_entry:
    mov [rel syscall_user_rsp], rsp
    mov rsp, [rel syscall_kernel_rsp]
    push USER_DATA_SELECTOR
    push qword [rel syscall_user_rsp]
    push r11
    push USER_CODE_SELECTOR
    push rcx
    push 0
    push SYSCALL_VECTOR
    SAVE_REGISTERS
    mov rdi, rsp
    call interrupt_dispatch
    jmp interrupt_return

; rdi points at a frame. The kernel registers are kept on this stack until cpu_leave_user unwinds to them.
cpu_enter_user:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [rel saved_kernel_rsp], rsp
    mov rsp, rdi
    jmp interrupt_return

cpu_leave_user:
    mov rax, rdi
    mov rsp, [rel saved_kernel_rsp]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

section .rodata
align 8
interrupt_stub_table:
%assign i 0
%rep STUB_COUNT
    dq interrupt_stub_%[i]
%assign i i + 1
%endrep

section .data
align 8
syscall_kernel_rsp:
    dq 0
syscall_user_rsp:
    dq 0
saved_kernel_rsp:
    dq 0
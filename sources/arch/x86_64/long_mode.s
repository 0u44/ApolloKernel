global apollo_long_mode_entry
extern apollo_kernel_main

section .text
bits 64

apollo_long_mode_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov rsp, apollo_stack_top
    and rsp, -16    ; Ensure 16-byte alignment

    cld

    call initialize_fpu

    call apollo_kernel_main

apollo_halt_loop:
    cli
    hlt
    jmp apollo_halt_loop

CR0_MP equ 1 << 1
CR0_EM equ 1 << 2
CR4_OSFXSR equ 1 << 9
CR4_OSXMMEXCPT equ 1 << 10

; The kernel is built without SSE, programs it runs expect it enabled
initialize_fpu:
    clts
    mov rax, cr0
    and rax, ~CR0_EM
    or rax, CR0_MP
    mov cr0, rax
    mov rax, cr4
    or rax, CR4_OSFXSR | CR4_OSXMMEXCPT
    mov cr4, rax
    fninit
    ret

section .bss
align 16
apollo_stack_bottom:
    resb 65536    ; 64KB kernel stack
apollo_stack_top:
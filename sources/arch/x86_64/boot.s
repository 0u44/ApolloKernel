global boot_entry_point
global multiboot_magic
global multiboot_info
extern apollo_long_mode_entry

P2_TABLE_COUNT equ 4
PAGE_TABLE_PAGES equ 2 + P2_TABLE_COUNT

section .multiboot
align 4

MB1_FLAGS equ 0x00000001          ; Page align modules so files can use them in place

multiboot1_header:
    dd 0x1BADB002                    ; Multiboot1 magic
    dd MB1_FLAGS
    dd -(0x1BADB002 + MB1_FLAGS)     ; Checksum

align 8
multiboot2_header:
    dd 0xe85250d6                    ; Multiboot2 magic
    dd 0                             ; Architecture (i386)
    dd multiboot2_end - multiboot2_header  ; Header length
    dd -(0xe85250d6 + 0 + (multiboot2_end - multiboot2_header))  ; Checksum

    align 8
    dw 6                             ; Type: module alignment
    dw 0
    dd 8

    align 8
    dw 0                             ; Type: end
    dw 0                             ; Flags  
    dd 8                             ; Size
multiboot2_end:

section .text
bits 32

boot_entry_point:
    cli
    
    mov esp, boot_stack_top
    mov [multiboot_magic], eax
    mov [multiboot_info], ebx
    
    cmp eax, 0x2BADB002    ; Multiboot1 magic
    je continue_boot
    cmp eax, 0x36d76289    ; Multiboot2 magic
    je continue_boot
    jmp error_no_multiboot

continue_boot:
    call check_cpu_features
    
    call setup_page_tables
    
    call enter_long_mode
    
    lgdt [gdt64_pointer]
    jmp 0x08:long_mode_start

check_cpu_features:
    pushfd
    pop eax
    mov ecx, eax
    xor eax, 1 << 21
    push eax
    popfd
    pushfd
    pop eax
    push ecx
    popfd
    cmp eax, ecx
    je error_no_cpuid
    
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb error_no_longmode
    
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz error_no_longmode
    
    ret

; Identity maps the first 4GB so PCI MMIO near the top of the 32 bit space is reachable
setup_page_tables:
    mov edi, p4_table
    xor eax, eax
    mov ecx, PAGE_TABLE_PAGES * 1024
    rep stosd

    mov dword [p4_table], p3_table + 0x03
    mov edi, p3_table
    mov eax, p2_tables + 0x03
    mov ecx, P2_TABLE_COUNT

.map_p3_table:
    mov [edi], eax
    add eax, 4096
    add edi, 8
    loop .map_p3_table

    mov edi, p2_tables
    mov ebx, 0x83          ; Present + writable + large page
    mov ecx, P2_TABLE_COUNT * 512

.map_p2_table:
    mov [edi], ebx
    add ebx, 0x200000      ; 2MB
    add edi, 8
    loop .map_p2_table

    ret

enter_long_mode:
    mov eax, p4_table
    mov cr3, eax
    
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax
    
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr
    
    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax
    
    ret

bits 64
long_mode_start:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    jmp apollo_long_mode_entry

bits 32

error_no_multiboot:
    mov dword [0xb8000], 0x4f524f45  ; "ER"
    mov dword [0xb8004], 0x4f3a4f52  ; "R:"
    mov dword [0xb8008], 0x4f424f4d  ; "MB"
    jmp halt

error_no_cpuid:
    mov dword [0xb8000], 0x4f524f45  ; "ER"
    mov dword [0xb8004], 0x4f3a4f52  ; "R:"
    mov dword [0xb8008], 0x4f554f43  ; "CU"
    jmp halt

error_no_longmode:
    mov dword [0xb8000], 0x4f524f45  ; "ER"
    mov dword [0xb8004], 0x4f3a4f52  ; "R:"
    mov dword [0xb8008], 0x4f4d4f4c  ; "LM"
    jmp halt

halt:
    hlt
    jmp halt

; The CPU sets the accessed bit in these descriptors, so they cannot live in rodata
section .data
align 8
gdt64:
    dq 0                             ; Null descriptor
    dq 0x00af9a000000ffff           ; 64-bit code segment
    dq 0x00af92000000ffff           ; 64-bit data segment
gdt64_end:

gdt64_pointer:
    dw gdt64_end - gdt64 - 1         ; Limit
    dd gdt64                         ; Base

multiboot_magic:
    dd 0
multiboot_info:
    dd 0

section .bss
align 4096
p4_table:
    resb 4096
p3_table:
    resb 4096
p2_tables:
    resb 4096 * P2_TABLE_COUNT

boot_stack_bottom:
    resb 16384
boot_stack_top:
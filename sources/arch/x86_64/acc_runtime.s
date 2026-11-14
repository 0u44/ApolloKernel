global acc_runtime_start
global acc_runtime_end

; The runtime built from sources/accrt, copied into each native acc program by acc_native.c
section .rodata
align 16
acc_runtime_start:
    incbin "objects/accrt/acc_runtime.bin"
acc_runtime_end:
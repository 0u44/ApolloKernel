global win32_runtime_start
global win32_runtime_end

; The Win32 runtime built from sources/win32, copied into each PE program by pe_loader.c
section .rodata
align 16
win32_runtime_start:
    incbin "objects/win32/runtime.bin"
win32_runtime_end:
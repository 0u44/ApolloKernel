OUTPUT_FORMAT("elf64-x86-64")
ENTRY(runtime_entry)

SECTIONS
{
    /* Matches WIN32_RUNTIME_BASE in headers/win32_runtime.h */
    . = 0x00007FF000000000;

    /* The loader reads the header at the first byte */
    .header : { KEEP(*(.runtime_header)) }
    /* The large code model puts everything in .l sections */
    .text : { *(.text) *(.text.*) *(.ltext) *(.ltext.*) }
    .rodata : { *(.rodata) *(.rodata.*) *(.lrodata) *(.lrodata.*) }
    .data : { *(.data) *(.data.*) *(.ldata) *(.ldata.*) }
    .bss : { *(.bss) *(.bss.*) *(.lbss) *(.lbss.*) *(COMMON) *(LARGE_COMMON) }
    __runtime_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note)
        *(.note.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}
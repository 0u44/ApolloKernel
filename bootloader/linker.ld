OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH("i386:x86-64")
ENTRY(boot_entry_point)

SECTIONS
{
    /* Load at 32MB, the space from 4MB up to here is left for program images */
    . = 0x2000000;
    __kernel_start = .;

    /* Multiboot needs its header near the start of the file */
    .multiboot :
    {
        KEEP(*(.multiboot))
    }

    /* Secure boot hashes .text then .rodata, the padding between them is not measured */
    . = ALIGN(0x1000);
    __text_start = .;

    .text :
    {
        *(.text)
        *(.text.*)
    }
    __text_end = .;

    . = ALIGN(0x1000);
    __rodata_start = .;
    .rodata :
    {
        *(.rodata)
        *(.rodata.*)
    }
    __rodata_end = .;

    /* Filled with the measured hash after linking, so it sits outside the measured range */
    . = ALIGN(0x1000);
    .secureboot :
    {
        KEEP(*(.secureboot))
    }

    . = ALIGN(0x1000);
    .data :
    {
        *(.data)
        *(.data.*)
    }

    /* Uninitialized data */
    . = ALIGN(0x1000);
    .bss :
    {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    }
    __kernel_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note)
        *(.note.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.gnu.hash)
        *(.gnu.version*)
        *(.rel.*)
        *(.rela.*)
    }
}
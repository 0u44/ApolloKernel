#include "program.h"
#include "memory.h"
#include "string_utils.h"

#define ELF_CLASS_64 2
#define ELF_DATA_LITTLE 1
#define ELF_MACHINE_X86_64 62
#define ELF_TYPE_EXEC 2
#define ELF_TYPE_DYN 3
#define EI_CLASS 4
#define EI_DATA 5
#define PT_LOAD 1
#define PT_INTERP 3
#define PT_PHDR 6
#define PF_W 2
#define ELF_MAX_SEGMENTS 64
// Where Linux puts position independent executables, out of the way of the program window
#define PIE_BASE 0x0000555555554000ULL

typedef struct {
    uint8_t ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} PACKED elf_header_t;

typedef struct {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
} PACKED elf_phdr_t;

static bool fail(char* error, const char* text) {
    string_copy(error, text);
    return false;
}

static const char* check_header(const elf_header_t* h, uint32_t size) {
    if (size < sizeof(elf_header_t)) return "ELF file is shorter than its header";
    if (h->ident[EI_CLASS] != ELF_CLASS_64 || h->ident[EI_DATA] != ELF_DATA_LITTLE) return "not a 64 bit little endian ELF file";
    if (h->machine != ELF_MACHINE_X86_64) return "ELF file is not built for x86_64";
    if (h->type != ELF_TYPE_EXEC && h->type != ELF_TYPE_DYN) return "ELF file is not an executable";
    if (h->phentsize != sizeof(elf_phdr_t) || h->phnum == 0 || h->phnum > ELF_MAX_SEGMENTS) return "ELF program headers are malformed";
    if (h->phoff > size || (uint64_t)h->phnum * sizeof(elf_phdr_t) > size - h->phoff) return "ELF program headers run past the end of the file";
    return NULL;
}

static const char* check_segments(const elf_phdr_t* ph, uint32_t count, uint32_t size, uint64_t base) {
    for (uint32_t i = 0; i < count; i++) {
        if (ph[i].type == PT_INTERP) return "dynamically linked, Apollo runs static ELF programs only (link with -static)";
        if (ph[i].type != PT_LOAD) continue;
        if (ph[i].filesz > ph[i].memsz || ph[i].offset > size || ph[i].filesz > size - ph[i].offset) return "ELF segment runs past the end of the file";
        if (!address_space_is_user(base + ph[i].vaddr, ph[i].memsz)) return "ELF segment is outside the addresses programs can use";
    }
    return NULL;
}

static bool load_segment(const elf_phdr_t* ph, const uint8_t* data, uint64_t base) {
    uint64_t start = base + ph->vaddr;
    uint64_t page = ALIGN_DOWN(start, PAGE_SIZE);
    uint64_t end = ALIGN_UP(start + ph->memsz, PAGE_SIZE);
    if (!address_space_map(&program.as, page, end - page, true) || !program_reserve(page, end - page)) return false;
    memcpy((void*)(uintptr_t)start, data + ph->offset, ph->filesz);
    memset((void*)(uintptr_t)(start + ph->filesz), 0, ph->memsz - ph->filesz);
    return true;
}

// Read only segments lose write access, then writable ones get it back where they share a page
static void protect_segments(const elf_phdr_t* ph, uint32_t count, uint64_t base) {
    for (int pass = 0; pass < 2; pass++) {
        for (uint32_t i = 0; i < count; i++) {
            if (ph[i].type != PT_LOAD || ((ph[i].flags & PF_W) != 0) != (pass == 1)) continue;
            address_space_protect(&program.as, base + ph[i].vaddr, ph[i].memsz, pass == 1);
        }
    }
}

static uint64_t phdr_address(const elf_header_t* h, const elf_phdr_t* ph, uint64_t base) {
    for (uint32_t i = 0; i < h->phnum; i++) {
        if (ph[i].type == PT_PHDR) return base + ph[i].vaddr;
    }
    for (uint32_t i = 0; i < h->phnum; i++) {
        if (ph[i].type == PT_LOAD && h->phoff >= ph[i].offset && h->phoff < ph[i].offset + ph[i].filesz) {
            return base + ph[i].vaddr + (h->phoff - ph[i].offset);
        }
    }
    return 0;
}

static void image_bounds(const elf_phdr_t* ph, uint32_t count, uint64_t base, uint64_t* low, uint64_t* high) {
    *low = ~0ULL;
    *high = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (ph[i].type != PT_LOAD) continue;
        if (base + ph[i].vaddr < *low) *low = base + ph[i].vaddr;
        if (base + ph[i].vaddr + ph[i].memsz > *high) *high = base + ph[i].vaddr + ph[i].memsz;
    }
}

bool elf_load(const uint8_t* data, uint32_t size, interrupt_frame_t* frame, char* error) {
    const elf_header_t* h = (const elf_header_t*)data;
    const char* problem = check_header(h, size);
    if (problem) return fail(error, problem);
    const elf_phdr_t* ph = (const elf_phdr_t*)(data + h->phoff);
    uint64_t base = h->type == ELF_TYPE_DYN ? PIE_BASE : 0;
    problem = check_segments(ph, h->phnum, size, base);
    if (problem) return fail(error, problem);
    for (uint32_t i = 0; i < h->phnum; i++) {
        if (ph[i].type == PT_LOAD && !load_segment(&ph[i], data, base)) return fail(error, "not enough memory for the program image");
    }
    protect_segments(ph, h->phnum, base);
    image_bounds(ph, h->phnum, base, &program.image_base, &program.image_end);
    if (program.image_end == 0) return fail(error, "ELF file has no loadable segments");
    program.brk_start = program.brk_end = ALIGN_UP(program.image_end, PAGE_SIZE);
    program.entry = base + h->entry;
    frame->rip = program.entry;
    frame->rsp = linux_build_stack(phdr_address(h, ph, base), h->phnum, h->phentsize);
    if (!frame->rsp) return fail(error, "the arguments do not fit on the stack");
    return true;
}
#include "memory.h"


extern uint32_t multiboot_magic;
extern uint32_t multiboot_info;
extern uint8_t __kernel_start[];
extern uint8_t __kernel_end[];

#define MULTIBOOT1_MAGIC 0x2BADB002
#define MULTIBOOT2_MAGIC 0x36D76289
#define MB1_FLAG_MEMORY (1u << 0)
#define MB1_FLAG_MODULES (1u << 3)
#define MB1_FLAG_MMAP (1u << 6)
#define MB2_TAG_END 0
#define MB2_TAG_MODULE 3
#define MB2_TAG_MEMINFO 4
#define MB2_TAG_MMAP 6
#define MB2_TAG_ALIGN 8
#define MMAP_AVAILABLE 1
#define KB 1024ULL
#define MB1_UPPER_BASE 0x100000ULL
// Only the identity mapped first 4GB is usable without more page tables
#define PHYSICAL_LIMIT 0x100000000ULL
#define FRAME_COUNT (PHYSICAL_LIMIT / PAGE_SIZE)
#define BITS_PER_WORD 64

typedef struct {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    uint32_t syms[4];
    uint32_t mmap_length;
    uint32_t mmap_addr;
} PACKED mb1_info_t;

typedef struct {
    uint32_t size;
    uint64_t base;
    uint64_t length;
    uint32_t type;
} PACKED mb1_mmap_entry_t;

typedef struct {
    uint32_t mod_start;
    uint32_t mod_end;
    uint32_t string;
    uint32_t reserved;
} PACKED mb1_module_t;

typedef struct {
    uint32_t type;
    uint32_t size;
} PACKED mb2_tag_t;

typedef struct {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t reserved;
} PACKED mb2_mmap_entry_t;

typedef struct {
    uint64_t start;
    uint32_t size;
    char name[BOOT_MODULE_NAME_LENGTH];
} boot_module_t;

static uint64_t frame_bitmap[FRAME_COUNT / BITS_PER_WORD];
static uint32_t free_frames;
static uint32_t total_frames;
static uint64_t search_hint;
static boot_module_t modules[BOOT_MODULES_MAX];
static uint32_t module_count;

/* bitmap, a set bit means the frame is in use */

static bool frame_used(uint64_t frame) {
    return (frame_bitmap[frame / BITS_PER_WORD] >> (frame % BITS_PER_WORD)) & 1;
}

static void set_frame(uint64_t frame, bool used) {
    uint64_t bit = 1ULL << (frame % BITS_PER_WORD);
    if (used) frame_bitmap[frame / BITS_PER_WORD] |= bit;
    else frame_bitmap[frame / BITS_PER_WORD] &= ~bit;
}

// Frames below the end of the kernel stay reserved, the window under the kernel belongs to programs
static void release_range(uint64_t base, uint64_t length) {
    uint64_t floor = ALIGN_UP((uint64_t)(uintptr_t)__kernel_end, PAGE_SIZE);
    uint64_t start = ALIGN_UP(base, PAGE_SIZE);
    uint64_t end = ALIGN_DOWN(base + length, PAGE_SIZE);
    if (start < floor) start = floor;
    if (end > PHYSICAL_LIMIT) end = PHYSICAL_LIMIT;
    for (uint64_t a = start; a < end; a += PAGE_SIZE) {
        if (!frame_used(a / PAGE_SIZE)) continue;
        set_frame(a / PAGE_SIZE, false);
        free_frames++;
        total_frames++;
    }
}

static void reserve_range(uint64_t base, uint64_t length) {
    for (uint64_t a = ALIGN_DOWN(base, PAGE_SIZE); a < base + length && a < PHYSICAL_LIMIT; a += PAGE_SIZE) {
        if (frame_used(a / PAGE_SIZE)) continue;
        set_frame(a / PAGE_SIZE, true);
        free_frames--;
    }
}

static void add_module(uint64_t start, uint64_t end, const char* cmdline) {
    if (module_count >= BOOT_MODULES_MAX || end < start) return;
    boot_module_t* m = &modules[module_count++];
    m->start = start;
    m->size = (uint32_t)(end - start);
    // The command line is the host path, keep the last component as the file name
    const char* name = cmdline ? cmdline : "module";
    for (const char* p = name; *p && *p != ' '; p++) if (*p == '/' || *p == '\\') name = p + 1;
    uint32_t n = 0;
    while (name[n] && name[n] != ' ' && n < BOOT_MODULE_NAME_LENGTH - 1) { m->name[n] = name[n]; n++; }
    m->name[n] = '\0';
}

/* multiboot parsing */

static void parse_multiboot1(const mb1_info_t* info) {
    if (info->flags & MB1_FLAG_MMAP) {
        uint64_t p = info->mmap_addr;
        while (p < (uint64_t)info->mmap_addr + info->mmap_length) {
            const mb1_mmap_entry_t* e = (const mb1_mmap_entry_t*)(uintptr_t)p;
            if (e->type == MMAP_AVAILABLE) release_range(e->base, e->length);
            p += e->size + sizeof(e->size);
        }
    } else if (info->flags & MB1_FLAG_MEMORY) {
        release_range(MB1_UPPER_BASE, (uint64_t)info->mem_upper * KB);
    }
    if (!(info->flags & MB1_FLAG_MODULES)) return;
    const mb1_module_t* mods = (const mb1_module_t*)(uintptr_t)info->mods_addr;
    for (uint32_t i = 0; i < info->mods_count; i++) {
        add_module(mods[i].mod_start, mods[i].mod_end, (const char*)(uintptr_t)mods[i].string);
    }
}

static void parse_multiboot2(uint64_t address) {
    uint32_t total = *(const uint32_t*)(uintptr_t)address;
    bool have_mmap = false;
    uint32_t mem_upper = 0;
    for (uint64_t p = address + 8; p < address + total;) {
        const mb2_tag_t* tag = (const mb2_tag_t*)(uintptr_t)p;
        if (tag->type == MB2_TAG_END) break;
        const uint8_t* body = (const uint8_t*)tag + sizeof(mb2_tag_t);
        if (tag->type == MB2_TAG_MMAP) {
            uint32_t entry_size = *(const uint32_t*)body;
            for (uint32_t off = 8; off + entry_size <= tag->size - sizeof(mb2_tag_t); off += entry_size) {
                const mb2_mmap_entry_t* e = (const mb2_mmap_entry_t*)(body + off);
                if (e->type == MMAP_AVAILABLE) release_range(e->base, e->length);
            }
            have_mmap = true;
        } else if (tag->type == MB2_TAG_MEMINFO) {
            mem_upper = ((const uint32_t*)body)[1];
        } else if (tag->type == MB2_TAG_MODULE) {
            const uint32_t* mod = (const uint32_t*)body;
            add_module(mod[0], mod[1], (const char*)(body + 8));
        }
        p += ALIGN_UP(tag->size, MB2_TAG_ALIGN);
    }
    if (!have_mmap && mem_upper) release_range(MB1_UPPER_BASE, (uint64_t)mem_upper * KB);
}

void memory_initialize(void) {
    for (uint64_t i = 0; i < FRAME_COUNT / BITS_PER_WORD; i++) frame_bitmap[i] = ~0ULL;
    free_frames = 0;
    total_frames = 0;
    module_count = 0;
    if (multiboot_magic == MULTIBOOT1_MAGIC) parse_multiboot1((const mb1_info_t*)(uintptr_t)multiboot_info);
    else if (multiboot_magic == MULTIBOOT2_MAGIC) parse_multiboot2(multiboot_info);
    for (uint32_t i = 0; i < module_count; i++) reserve_range(modules[i].start, modules[i].size);
    search_hint = 0;
}

/* frames */

static void zero_frames(uint64_t address, uint32_t count) {
    memset((void*)(uintptr_t)address, 0, (size_t)count * PAGE_SIZE);
}

uint64_t frame_alloc(void) {
    return frame_alloc_contiguous(1);
}

uint64_t frame_alloc_contiguous(uint32_t count) {
    if (count == 0 || count > free_frames) return 0;
    for (uint64_t pass = 0; pass < 2; pass++) {
        uint64_t run = 0;
        uint64_t start = pass == 0 ? search_hint : 0;
        uint64_t limit = pass == 0 ? FRAME_COUNT : search_hint + count;
        for (uint64_t f = start; f < limit && f < FRAME_COUNT; f++) {
            if (frame_used(f)) { run = 0; continue; }
            if (++run < count) continue;
            uint64_t first = f + 1 - count;
            for (uint64_t g = first; g <= f; g++) set_frame(g, true);
            free_frames -= count;
            search_hint = f + 1;
            zero_frames(first * PAGE_SIZE, count);
            return first * PAGE_SIZE;
        }
    }
    return 0;
}

void frame_free(uint64_t address) {
    frame_free_contiguous(address, 1);
}

void frame_free_contiguous(uint64_t address, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        uint64_t f = address / PAGE_SIZE + i;
        if (f >= FRAME_COUNT || !frame_used(f)) continue;
        set_frame(f, false);
        free_frames++;
    }
    if (address / PAGE_SIZE < search_hint) search_hint = address / PAGE_SIZE;
}

uint32_t memory_free_frames(void) {
    return free_frames;
}

uint32_t memory_total_frames(void) {
    return total_frames;
}

uint64_t memory_user_window_end(void) {
    return (uint64_t)(uintptr_t)__kernel_start;
}

/* boot modules */

uint32_t boot_module_count(void) {
    return module_count;
}

bool boot_module_get(uint32_t index, uint8_t** data, uint32_t* size, const char** name) {
    if (index >= module_count) return false;
    *data = (uint8_t*)(uintptr_t)modules[index].start;
    *size = modules[index].size;
    *name = modules[index].name;
    return true;
}
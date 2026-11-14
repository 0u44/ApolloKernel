#include "address_space.h"
#include "memory.h"
#include "cpu.h"

#define PTE_PRESENT (1ULL << 0)
#define PTE_WRITE (1ULL << 1)
#define PTE_USER (1ULL << 2)
#define PTE_LARGE (1ULL << 7)
#define PTE_ADDRESS 0x000FFFFFFFFFF000ULL
#define TABLE_ENTRIES 512
#define LARGE_PAGE_SIZE 0x200000ULL
// The boot code identity maps 4GB with four P2 tables, those P3 slots stay shared with the kernel
#define IDENTITY_P3_SLOTS 4
// P4 slots 1 to 255 are the rest of the lower half, the upper half is never given to programs
#define USER_P4_LAST 255

static inline uint64_t* table_at(uint64_t physical) {
    return (uint64_t*)(uintptr_t)(physical & PTE_ADDRESS);
}

static inline uint32_t index_of(uint64_t address, uint32_t shift) {
    return (uint32_t)((address >> shift) & (TABLE_ENTRIES - 1));
}

static void invalidate(const address_space_t* as, uint64_t address) {
    if ((cpu_read_cr3() & PTE_ADDRESS) == as->p4) __asm__ volatile("invlpg (%0)" : : "r"(address) : "memory");
}

bool address_space_is_user(uint64_t address, uint64_t length) {
    uint64_t end = address + length;
    if (end < address) return false;
    if (address >= USER_WINDOW_START && end <= memory_user_window_end()) return true;
    return address >= USER_HIGH_START && end <= USER_HIGH_END;
}

// The window P2 replaces the kernel's first P2 so the 2MB pages from 4MB up to the kernel can hold program pages
bool address_space_create(address_space_t* as) {
    uint64_t* kernel_p4 = table_at(cpu_kernel_cr3());
    uint64_t* kernel_p3 = table_at(kernel_p4[0]);
    uint64_t* kernel_p2 = table_at(kernel_p3[0]);
    as->p4 = frame_alloc();
    uint64_t p3 = frame_alloc();
    as->window_p2 = frame_alloc();
    as->pages = 0;
    if (!as->p4 || !p3 || !as->window_p2) {
        if (as->p4) frame_free(as->p4);
        if (p3) frame_free(p3);
        if (as->window_p2) frame_free(as->window_p2);
        return false;
    }
    uint64_t* window = table_at(as->window_p2);
    for (uint32_t i = 0; i < TABLE_ENTRIES; i++) {
        uint64_t address = (uint64_t)i * LARGE_PAGE_SIZE;
        bool in_window = address >= USER_WINDOW_START && address < memory_user_window_end();
        window[i] = in_window ? 0 : kernel_p2[i];
    }
    uint64_t* user_p3 = table_at(p3);
    for (uint32_t i = 1; i < IDENTITY_P3_SLOTS; i++) user_p3[i] = kernel_p3[i] | PTE_USER;
    user_p3[0] = as->window_p2 | PTE_PRESENT | PTE_WRITE | PTE_USER;
    table_at(as->p4)[0] = p3 | PTE_PRESENT | PTE_WRITE | PTE_USER;
    return true;
}

void address_space_activate(const address_space_t* as) {
    cpu_write_cr3(as ? as->p4 : cpu_kernel_cr3());
}

/* walking */

static uint64_t* next_table(uint64_t* entry, bool create) {
    if (!(*entry & PTE_PRESENT)) {
        if (!create) return NULL;
        uint64_t frame = frame_alloc();
        if (!frame) return NULL;
        *entry = frame | PTE_PRESENT | PTE_WRITE | PTE_USER;
    }
    if (*entry & PTE_LARGE) return NULL;
    return table_at(*entry);
}

// Returns the last level entry for a user address, or NULL when it is not mapped and create is false
static uint64_t* walk(const address_space_t* as, uint64_t address, bool create) {
    if (!address_space_is_user(address, 1)) return NULL;
    uint64_t* p3 = next_table(&table_at(as->p4)[index_of(address, 39)], create);
    if (!p3) return NULL;
    uint64_t* p2 = next_table(&p3[index_of(address, 30)], create);
    if (!p2) return NULL;
    uint64_t* p1 = next_table(&p2[index_of(address, 21)], create);
    if (!p1) return NULL;
    return &p1[index_of(address, 12)];
}

bool address_space_map(address_space_t* as, uint64_t address, uint64_t length, bool writable) {
    uint64_t start = ALIGN_DOWN(address, PAGE_SIZE);
    uint64_t end = ALIGN_UP(address + length, PAGE_SIZE);
    if (!address_space_is_user(start, end - start)) return false;
    for (uint64_t a = start; a < end; a += PAGE_SIZE) {
        uint64_t* pte = walk(as, a, true);
        if (!pte) return false;
        if (*pte & PTE_PRESENT) {
            if (writable) *pte |= PTE_WRITE;
            continue;
        }
        uint64_t frame = frame_alloc();
        if (!frame) return false;
        *pte = frame | PTE_PRESENT | PTE_USER | (writable ? PTE_WRITE : 0);
        as->pages++;
        invalidate(as, a);
    }
    return true;
}

void address_space_unmap(address_space_t* as, uint64_t address, uint64_t length) {
    uint64_t end = ALIGN_UP(address + length, PAGE_SIZE);
    for (uint64_t a = ALIGN_DOWN(address, PAGE_SIZE); a < end; a += PAGE_SIZE) {
        uint64_t* pte = walk(as, a, false);
        if (!pte || !(*pte & PTE_PRESENT)) continue;
        frame_free(*pte & PTE_ADDRESS);
        *pte = 0;
        as->pages--;
        invalidate(as, a);
    }
}

void address_space_protect(address_space_t* as, uint64_t address, uint64_t length, bool writable) {
    uint64_t end = ALIGN_UP(address + length, PAGE_SIZE);
    for (uint64_t a = ALIGN_DOWN(address, PAGE_SIZE); a < end; a += PAGE_SIZE) {
        uint64_t* pte = walk(as, a, false);
        if (!pte || !(*pte & PTE_PRESENT)) continue;
        *pte = writable ? (*pte | PTE_WRITE) : (*pte & ~PTE_WRITE);
        invalidate(as, a);
    }
}

bool address_space_is_mapped(const address_space_t* as, uint64_t address, bool write) {
    uint64_t* pte = walk(as, address, false);
    if (!pte || !(*pte & PTE_PRESENT)) return false;
    return !write || (*pte & PTE_WRITE);
}

bool address_space_range_mapped(const address_space_t* as, uint64_t address, uint64_t length, bool write) {
    if (length == 0) return true;
    if (!address_space_is_user(address, length)) return false;
    uint64_t end = address + length;
    for (uint64_t a = ALIGN_DOWN(address, PAGE_SIZE); a < end; a += PAGE_SIZE) {
        if (!address_space_is_mapped(as, a, write)) return false;
    }
    return true;
}

/* teardown */

static void free_table(uint64_t entry, uint32_t level) {
    uint64_t* table = table_at(entry);
    for (uint32_t i = 0; i < TABLE_ENTRIES; i++) {
        if (!(table[i] & PTE_PRESENT)) continue;
        if (level == 1) frame_free(table[i] & PTE_ADDRESS);
        else free_table(table[i], level - 1);
    }
    frame_free(entry & PTE_ADDRESS);
}

// Frees every table and page the program owned, the shared kernel tables are left alone
void address_space_destroy(address_space_t* as) {
    if (!as->p4) return;
    if ((cpu_read_cr3() & PTE_ADDRESS) == as->p4) address_space_activate(NULL);
    uint64_t* p4 = table_at(as->p4);
    uint64_t* p3 = table_at(p4[0]);
    uint64_t* window = table_at(as->window_p2);
    for (uint32_t i = 0; i < TABLE_ENTRIES; i++) {
        uint64_t address = (uint64_t)i * LARGE_PAGE_SIZE;
        bool in_window = address >= USER_WINDOW_START && address < memory_user_window_end();
        if (in_window && (window[i] & PTE_PRESENT)) free_table(window[i], 1);
    }
    for (uint32_t i = IDENTITY_P3_SLOTS; i < TABLE_ENTRIES; i++) {
        if (p3[i] & PTE_PRESENT) free_table(p3[i], 2);
    }
    for (uint32_t i = 1; i <= USER_P4_LAST; i++) {
        if (p4[i] & PTE_PRESENT) free_table(p4[i], 3);
    }
    frame_free(as->window_p2);
    frame_free(p4[0] & PTE_ADDRESS);
    frame_free(as->p4);
    as->p4 = 0;
    as->window_p2 = 0;
    as->pages = 0;
}
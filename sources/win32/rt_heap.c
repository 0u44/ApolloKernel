#include "runtime.h"

#define HEAP_ZERO_MEMORY 0x08
#define HEAP_GENERATE_EXCEPTIONS 0x04
#define HEAP_REALLOC_IN_PLACE_ONLY 0x10
#define ALIGNMENT 16
#define HEADER_SIZE 16
#define SMALL_LIMIT 1024
#define SMALL_BINS (SMALL_LIMIT / ALIGNMENT)
#define HUGE_LIMIT (256 * 1024)
#define ARENA_SIZE (1024 * 1024)
#define SPLIT_MINIMUM 64
#define FLAG_USED 0x1ULL
#define FLAG_HUGE 0x2ULL
#define FLAG_MASK 0xFULL
#define MAGIC 0xA9E5ULL
#define MAGIC_SHIFT 48
#define REQUESTED_MASK ((1ULL << MAGIC_SHIFT) - 1)
#define PROT_READ_WRITE 3
#define MAP_PRIVATE_ANONYMOUS 0x22

typedef struct {
    uint64_t capacity;
    uint64_t info;
} block_t;

typedef struct free_block {
    struct free_block* next;
} free_block_t;

static free_block_t* small_bins[SMALL_BINS + 1];
static free_block_t* large_list;
static uint8_t* arena_next;
static uint8_t* arena_end;
static uint64_t process_heap_marker;

static block_t* header_of(void* payload) {
    return (block_t*)((uint8_t*)payload - HEADER_SIZE);
}

static uint64_t capacity_of(const block_t* b) {
    return b->capacity & ~FLAG_MASK;
}

static bool valid_block(const block_t* b) {
    return (b->info >> MAGIC_SHIFT) == MAGIC && (b->capacity & FLAG_USED);
}

static void* finish(block_t* b, uint64_t capacity, uint64_t requested, uint64_t flags) {
    b->capacity = capacity | flags | FLAG_USED;
    b->info = requested | (MAGIC << MAGIC_SHIFT);
    return (uint8_t*)b + HEADER_SIZE;
}

static void* map_pages(uint64_t length) {
    int64_t r = sys6(LINUX_MMAP, 0, length, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, (uint64_t)-1, 0);
    return r < 0 ? NULL : (void*)r;
}

static block_t* carve(uint64_t capacity) {
    uint64_t need = capacity + HEADER_SIZE;
    if (!arena_next || (uint64_t)(arena_end - arena_next) < need) {
        uint8_t* arena = map_pages(ARENA_SIZE);
        if (!arena) return NULL;
        arena_next = arena;
        arena_end = arena + ARENA_SIZE;
    }
    block_t* b = (block_t*)arena_next;
    arena_next += need;
    return b;
}

static block_t* take_large(uint64_t capacity) {
    for (free_block_t** link = &large_list; *link; link = &(*link)->next) {
        block_t* b = header_of(*link);
        uint64_t have = capacity_of(b);
        if (have < capacity) continue;
        *link = (*link)->next;
        if (have - capacity >= SPLIT_MINIMUM + HEADER_SIZE) {
            block_t* rest = (block_t*)((uint8_t*)b + HEADER_SIZE + capacity);
            rest->capacity = have - capacity - HEADER_SIZE;
            rest->info = MAGIC << MAGIC_SHIFT;
            free_block_t* node = (free_block_t*)((uint8_t*)rest + HEADER_SIZE);
            node->next = large_list;
            large_list = node;
            b->capacity = capacity;
        }
        return b;
    }
    return NULL;
}

void* rt_alloc(SIZE_T size) {
    uint64_t capacity = ALIGN_UP(size ? size : 1, ALIGNMENT);
    if (size > REQUESTED_MASK) return NULL;
    if (capacity >= HUGE_LIMIT) {
        block_t* b = map_pages(capacity + HEADER_SIZE);
        return b ? finish(b, capacity, size, FLAG_HUGE) : NULL;
    }
    if (capacity <= SMALL_LIMIT) {
        uint64_t bin = capacity / ALIGNMENT;
        if (small_bins[bin]) {
            free_block_t* node = small_bins[bin];
            small_bins[bin] = node->next;
            return finish(header_of(node), capacity, size, 0);
        }
    } else {
        block_t* reused = take_large(capacity);
        if (reused) return finish(reused, capacity_of(reused), size, 0);
    }
    block_t* b = carve(capacity);
    return b ? finish(b, capacity, size, 0) : NULL;
}

void* rt_alloc_zero(SIZE_T size) {
    void* p = rt_alloc(size);
    if (p) memset(p, 0, size);
    return p;
}

void rt_free(void* payload) {
    if (!payload) return;
    block_t* b = header_of(payload);
    uint64_t capacity = capacity_of(b);
    if (b->capacity & FLAG_HUGE) {
        sys2(LINUX_MUNMAP, b, capacity + HEADER_SIZE);
        return;
    }
    b->capacity = capacity;
    free_block_t* node = payload;
    if (capacity <= SMALL_LIMIT) {
        node->next = small_bins[capacity / ALIGNMENT];
        small_bins[capacity / ALIGNMENT] = node;
    } else {
        node->next = large_list;
        large_list = node;
    }
}

void rt_heap_initialize(void) {
    process_heap_marker = MAGIC;
}

HANDLE rt_process_heap(void) {
    return &process_heap_marker;
}

static bool heap_ok(HANDLE heap) {
    if (heap == &process_heap_marker) return true;
    rt_set_last_error(ERROR_INVALID_HANDLE);
    return false;
}

WINAPI HANDLE GetProcessHeap(void) {
    return rt_process_heap();
}

WINAPI void* HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size) {
    if (!heap_ok(heap)) return NULL;
    void* p = (flags & HEAP_ZERO_MEMORY) ? rt_alloc_zero(size) : rt_alloc(size);
    if (!p && (flags & HEAP_GENERATE_EXCEPTIONS)) rt_raise_status(STATUS_NO_MEMORY);
    if (!p) rt_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    return p;
}

WINAPI BOOL HeapFree(HANDLE heap, DWORD flags, void* block) {
    (void)flags;
    if (!heap_ok(heap)) return FALSE;
    if (!block) return TRUE;
    if (!valid_block(header_of(block))) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    rt_free(block);
    return TRUE;
}

WINAPI SIZE_T HeapSize(HANDLE heap, DWORD flags, const void* block) {
    (void)flags;
    if (!heap_ok(heap) || !block || !valid_block(header_of((void*)block))) return (SIZE_T)-1;
    return header_of((void*)block)->info & REQUESTED_MASK;
}

WINAPI void* HeapReAlloc(HANDLE heap, DWORD flags, void* block, SIZE_T size) {
    if (!heap_ok(heap)) return NULL;
    if (!block || !valid_block(header_of(block))) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    block_t* b = header_of(block);
    uint64_t old_size = b->info & REQUESTED_MASK;
    if (size <= capacity_of(b)) {
        if ((flags & HEAP_ZERO_MEMORY) && size > old_size) memset((uint8_t*)block + old_size, 0, size - old_size);
        b->info = size | (MAGIC << MAGIC_SHIFT);
        return block;
    }
    if (flags & HEAP_REALLOC_IN_PLACE_ONLY) {
        rt_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    void* moved = HeapAlloc(heap, flags, size);
    if (!moved) return NULL;
    memcpy(moved, block, old_size);
    rt_free(block);
    return moved;
}
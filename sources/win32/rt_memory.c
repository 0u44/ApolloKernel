#include "runtime.h"

#define PAGE 4096
#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_DECOMMIT 0x4000
#define MEM_RELEASE 0x8000
#define MEM_FREE 0x10000
#define MEM_PRIVATE 0x20000
#define MEM_IMAGE 0x1000000
#define LINUX_PROT_NONE 0
#define LINUX_PROT_READ 1
#define LINUX_PROT_WRITE 2
#define MAP_PRIVATE_ANONYMOUS 0x22
#define MAP_FIXED 0x10
#define MAP_FIXED_NOREPLACE 0x100000
#define STATE_FREE 0
#define STATE_RESERVED 1
#define STATE_COMMITTED 2
#define FILETIME_UNIX_EPOCH 116444736000000000ULL
#define NS_PER_TICK 100
#define TICKS_PER_SECOND 10000000ULL
#define NS_PER_MS 1000000ULL
#define CLOCK_MONOTONIC 1

typedef struct {
    uint64_t region_base;
    uint64_t region_size;
    uint64_t run_size;
    uint32_t state;
    uint32_t writable;
} memory_info_t;

typedef struct {
    void* base;
    void* allocation_base;
    DWORD allocation_protect;
    uint16_t partition;
    uint16_t pad0;
    SIZE_T region_size;
    DWORD state;
    DWORD protect;
    DWORD type;
    DWORD pad1;
} MEMORY_BASIC_INFORMATION;

static bool writable_protection(DWORD protect) {
    return protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
}

static int linux_protection(DWORD protect) {
    if (protect & PAGE_NOACCESS) return LINUX_PROT_NONE;
    return LINUX_PROT_READ | (writable_protection(protect) ? LINUX_PROT_WRITE : 0);
}

static memory_info_t query(uint64_t address) {
    memory_info_t info;
    memset(&info, 0, sizeof(info));
    sys2(APOLLO_QUERY_MEMORY, address, &info);
    return info;
}

static DWORD effective_protection(const memory_info_t* info) {
    if (info->state != STATE_COMMITTED) return info->state == STATE_RESERVED ? PAGE_NOACCESS : 0;
    return info->writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
}

WINAPI BOOL VirtualProtect(void* address, SIZE_T size, DWORD protect, DWORD* old) {
    uint64_t start = ALIGN_DOWN((uint64_t)address, PAGE);
    uint64_t end = ALIGN_UP((uint64_t)address + size, PAGE);
    memory_info_t info = query(start);
    if (info.state != STATE_COMMITTED) {
        rt_set_last_error(ERROR_INVALID_ADDRESS);
        return FALSE;
    }
    if (old) *old = effective_protection(&info);
    int64_t r = sys3(LINUX_MPROTECT, start, end - start, linux_protection(protect));
    if (r < 0) {
        rt_set_last_error(ERROR_INVALID_ADDRESS);
        return FALSE;
    }
    return TRUE;
}

WINAPI SIZE_T VirtualQuery(const void* address, MEMORY_BASIC_INFORMATION* out, SIZE_T length) {
    if (length < sizeof(*out)) {
        rt_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    uint64_t page = ALIGN_DOWN((uint64_t)address, PAGE);
    memory_info_t info = query(page);
    memset(out, 0, sizeof(*out));
    out->base = (void*)page;
    if (info.state == STATE_FREE) {
        out->state = MEM_FREE;
        out->protect = PAGE_NOACCESS;
        out->region_size = PAGE;
        return sizeof(*out);
    }
    bool image = info.region_base == rt_image_base();
    out->allocation_base = (void*)info.region_base;
    out->allocation_protect = image ? PAGE_EXECUTE_WRITECOPY : PAGE_READWRITE;
    out->region_size = info.run_size;
    out->state = info.state == STATE_COMMITTED ? MEM_COMMIT : MEM_RESERVE;
    out->protect = info.state == STATE_COMMITTED ? effective_protection(&info) : 0;
    out->type = image ? MEM_IMAGE : MEM_PRIVATE;
    return sizeof(*out);
}

WINAPI void* VirtualAlloc(void* address, SIZE_T size, DWORD type, DWORD protect) {
    uint64_t length = ALIGN_UP(size, PAGE);
    if (length == 0 || !(type & (MEM_COMMIT | MEM_RESERVE))) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    memory_info_t info = address ? query((uint64_t)address) : (memory_info_t){0};
    if ((type & MEM_COMMIT) && !(type & MEM_RESERVE) && info.state != STATE_FREE) {
        uint64_t start = ALIGN_DOWN((uint64_t)address, PAGE);
        if (sys3(LINUX_MPROTECT, start, ALIGN_UP((uint64_t)address + size, PAGE) - start, linux_protection(protect)) < 0) {
            rt_set_last_error(ERROR_INVALID_ADDRESS);
            return NULL;
        }
        return (void*)start;
    }
    int prot = (type & MEM_COMMIT) ? linux_protection(protect) : LINUX_PROT_NONE;
    uint64_t flags = MAP_PRIVATE_ANONYMOUS | (address ? MAP_FIXED_NOREPLACE : 0);
    int64_t r = sys6(LINUX_MMAP, ALIGN_DOWN((uint64_t)address, PAGE), length, prot, flags, (uint64_t)-1, 0);
    if (r < 0) {
        rt_set_last_error(address ? ERROR_INVALID_ADDRESS : ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return (void*)r;
}

WINAPI BOOL VirtualFree(void* address, SIZE_T size, DWORD type) {
    memory_info_t info = query((uint64_t)address);
    if (info.state == STATE_FREE) {
        rt_set_last_error(ERROR_INVALID_ADDRESS);
        return FALSE;
    }
    if (type == MEM_RELEASE) {
        if (size != 0 || (uint64_t)address != info.region_base) {
            rt_set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        return sys2(LINUX_MUNMAP, info.region_base, info.region_size) == 0;
    }
    if (type != MEM_DECOMMIT) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    uint64_t start = ALIGN_DOWN((uint64_t)address, PAGE);
    uint64_t length = size ? ALIGN_UP((uint64_t)address + size, PAGE) - start : info.region_base + info.region_size - start;
    sys2(LINUX_MUNMAP, start, length);
    return sys6(LINUX_MMAP, start, length, LINUX_PROT_NONE, MAP_PRIVATE_ANONYMOUS | MAP_FIXED, (uint64_t)-1, 0) >= 0;
}

static uint64_t monotonic_ns(void) {
    linux_timespec_t ts;
    sys2(LINUX_CLOCK_GETTIME, CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.seconds * 1000000000ULL + (uint64_t)ts.nanoseconds;
}

WINAPI BOOL QueryPerformanceCounter(int64_t* counter) {
    *counter = (int64_t)(monotonic_ns() / NS_PER_TICK);
    return TRUE;
}

WINAPI BOOL QueryPerformanceFrequency(int64_t* frequency) {
    *frequency = (int64_t)TICKS_PER_SECOND;
    return TRUE;
}

WINAPI void GetSystemTimeAsFileTime(uint64_t* filetime) {
    *filetime = rt_now_ns() / NS_PER_TICK + FILETIME_UNIX_EPOCH;
}

WINAPI void GetSystemTimePreciseAsFileTime(uint64_t* filetime) {
    *filetime = rt_now_ns() / NS_PER_TICK + FILETIME_UNIX_EPOCH;
}

WINAPI DWORD GetTickCount(void) {
    return (DWORD)(monotonic_ns() / NS_PER_MS);
}

WINAPI uint64_t GetTickCount64(void) {
    return monotonic_ns() / NS_PER_MS;
}
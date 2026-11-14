#include "runtime.h"

#define TEB_TLS_SLOTS 0x1480
#define TEB_TLS_EXPANSION 0x1780
#define TLS_SLOTS 64
#define TLS_EXPANSION_SLOTS 1024
#define TLS_OUT_OF_INDEXES 0xFFFFFFFFu
#define FLS_SLOTS 128
#define FLS_OUT_OF_INDEXES 0xFFFFFFFFu
#define NS_PER_MS 1000000ULL

typedef void (WINAPI *fls_callback_t)(void* value);

typedef struct {
    void* debug_info;
    LONG lock_count;
    LONG recursion_count;
    HANDLE owning_thread;
    HANDLE lock_semaphore;
    ULONG_PTR spin_count;
} CRITICAL_SECTION;

static bool tls_used[TLS_SLOTS + TLS_EXPANSION_SLOTS];
static bool fls_used[FLS_SLOTS];
static void* fls_values[FLS_SLOTS];
static fls_callback_t fls_callbacks[FLS_SLOTS];

static uint8_t* current_teb(void) {
    uint8_t* teb;
    __asm__ volatile("mov %%gs:0x30, %0" : "=r"(teb));
    return teb;
}

static void** tls_slot(DWORD index) {
    uint8_t* teb = current_teb();
    if (index < TLS_SLOTS) return (void**)(teb + TEB_TLS_SLOTS) + index;
    void*** expansion = (void***)(teb + TEB_TLS_EXPANSION);
    if (!*expansion) *expansion = rt_alloc_zero(TLS_EXPANSION_SLOTS * sizeof(void*));
    return *expansion ? *expansion + (index - TLS_SLOTS) : NULL;
}

WINAPI DWORD TlsAlloc(void) {
    for (DWORD i = 0; i < TLS_SLOTS + TLS_EXPANSION_SLOTS; i++) {
        if (tls_used[i]) continue;
        void** slot = tls_slot(i);
        if (!slot) break;
        tls_used[i] = true;
        *slot = NULL;
        return i;
    }
    rt_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    return TLS_OUT_OF_INDEXES;
}

WINAPI void* TlsGetValue(DWORD index) {
    if (index >= TLS_SLOTS + TLS_EXPANSION_SLOTS || !tls_used[index]) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    rt_set_last_error(ERROR_SUCCESS);
    return *tls_slot(index);
}

WINAPI BOOL TlsSetValue(DWORD index, void* value) {
    if (index >= TLS_SLOTS + TLS_EXPANSION_SLOTS || !tls_used[index]) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *tls_slot(index) = value;
    return TRUE;
}

WINAPI BOOL TlsFree(DWORD index) {
    if (index >= TLS_SLOTS + TLS_EXPANSION_SLOTS || !tls_used[index]) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    tls_used[index] = false;
    return TRUE;
}

WINAPI DWORD FlsAlloc(fls_callback_t callback) {
    for (DWORD i = 0; i < FLS_SLOTS; i++) {
        if (fls_used[i]) continue;
        fls_used[i] = true;
        fls_values[i] = NULL;
        fls_callbacks[i] = callback;
        return i;
    }
    rt_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    return FLS_OUT_OF_INDEXES;
}

WINAPI void* FlsGetValue(DWORD index) {
    if (index >= FLS_SLOTS || !fls_used[index]) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    rt_set_last_error(ERROR_SUCCESS);
    return fls_values[index];
}

WINAPI BOOL FlsSetValue(DWORD index, void* value) {
    if (index >= FLS_SLOTS || !fls_used[index]) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    fls_values[index] = value;
    return TRUE;
}

WINAPI BOOL FlsFree(DWORD index) {
    if (index >= FLS_SLOTS || !fls_used[index]) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (fls_callbacks[index] && fls_values[index]) fls_callbacks[index](fls_values[index]);
    fls_used[index] = false;
    return TRUE;
}

static void initialize_section(CRITICAL_SECTION* section, DWORD spin) {
    memset(section, 0, sizeof(*section));
    section->lock_count = -1;
    section->spin_count = spin;
}

WINAPI BOOL InitializeCriticalSectionAndSpinCount(CRITICAL_SECTION* section, DWORD spin) {
    initialize_section(section, spin);
    return TRUE;
}

WINAPI BOOL InitializeCriticalSectionEx(CRITICAL_SECTION* section, DWORD spin, DWORD flags) {
    (void)flags;
    initialize_section(section, spin);
    return TRUE;
}

WINAPI void EnterCriticalSection(CRITICAL_SECTION* section) {
    section->lock_count++;
    section->recursion_count++;
    section->owning_thread = (HANDLE)(uint64_t)sys0(LINUX_GETTID);
}

WINAPI void LeaveCriticalSection(CRITICAL_SECTION* section) {
    section->lock_count--;
    if (--section->recursion_count == 0) section->owning_thread = NULL;
}

WINAPI void DeleteCriticalSection(CRITICAL_SECTION* section) {
    memset(section, 0, sizeof(*section));
}

WINAPI void AcquireSRWLockExclusive(void** lock) {
    if (*lock) rt_fatal("Deadlock: SRW lock acquired twice by the only thread", STATUS_DEADLOCK);
    *lock = (void*)1;
}

WINAPI void ReleaseSRWLockExclusive(void** lock) {
    *lock = NULL;
}

WINAPI void Sleep(DWORD milliseconds) {
    linux_timespec_t ts = {milliseconds / 1000, (int64_t)(milliseconds % 1000) * (int64_t)NS_PER_MS};
    while (sys2(LINUX_NANOSLEEP, &ts, &ts) < 0) {}
}

WINAPI BOOL SleepConditionVariableSRW(void** variable, void** lock, DWORD milliseconds, DWORD flags) {
    (void)variable;
    (void)flags;
    if (milliseconds == INFINITE) rt_fatal("Deadlock: waiting on a condition variable no other thread can wake", STATUS_DEADLOCK);
    ReleaseSRWLockExclusive(lock);
    Sleep(milliseconds);
    AcquireSRWLockExclusive(lock);
    rt_set_last_error(ERROR_TIMEOUT);
    return FALSE;
}

WINAPI void WakeAllConditionVariable(void** variable) {
    (void)variable;
}
#ifndef APOLLO_WIN32_RUNTIME_INTERNAL_H
#define APOLLO_WIN32_RUNTIME_INTERNAL_H

#include "types.h"
#include "win32_runtime.h"

#define WINAPI __attribute__((ms_abi))

typedef uint16_t WCHAR;
typedef int32_t BOOL;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint32_t UINT;
typedef void* HANDLE;
typedef void* HMODULE;
typedef uint64_t SIZE_T;
typedef uint64_t ULONG_PTR;
typedef int64_t LONG_PTR;
typedef uint32_t LCID;

#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#define CURRENT_PROCESS_HANDLE ((HANDLE)(LONG_PTR)-1)
#define CURRENT_THREAD_HANDLE ((HANDLE)(LONG_PTR)-2)
#define INFINITE 0xFFFFFFFFu

#define ERROR_SUCCESS 0
#define ERROR_INVALID_FUNCTION 1
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_TOO_MANY_OPEN_FILES 4
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_HANDLE 6
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_INVALID_DATA 13
#define ERROR_OUTOFMEMORY 14
#define ERROR_NO_MORE_FILES 18
#define ERROR_HANDLE_EOF 38
#define ERROR_NOT_SUPPORTED 50
#define ERROR_FILE_EXISTS 80
#define ERROR_INVALID_PARAMETER 87
#define ERROR_BROKEN_PIPE 109
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_MOD_NOT_FOUND 126
#define ERROR_PROC_NOT_FOUND 127
#define ERROR_DIR_NOT_EMPTY 145
#define ERROR_ALREADY_EXISTS 183
#define ERROR_ENVVAR_NOT_FOUND 203
#define ERROR_INVALID_ADDRESS 487
#define ERROR_INVALID_FLAGS 1004
#define ERROR_NO_UNICODE_TRANSLATION 1113
#define ERROR_TIMEOUT 1460

#define STATUS_SUCCESS 0x00000000u
#define STATUS_BREAKPOINT 0x80000003u
#define STATUS_DATATYPE_MISALIGNMENT 0x80000002u
#define STATUS_ACCESS_VIOLATION 0xC0000005u
#define STATUS_NO_MEMORY 0xC0000017u
#define STATUS_ILLEGAL_INSTRUCTION 0xC000001Du
#define STATUS_NONCONTINUABLE_EXCEPTION 0xC0000025u
#define STATUS_INVALID_DISPOSITION 0xC0000026u
#define STATUS_UNWIND 0xC0000027u
#define STATUS_BAD_STACK 0xC0000028u
#define STATUS_INVALID_UNWIND_TARGET 0xC0000029u
#define STATUS_FLOAT_INVALID_OPERATION 0xC0000090u
#define STATUS_INTEGER_DIVIDE_BY_ZERO 0xC0000094u
#define STATUS_STACK_OVERFLOW 0xC00000FDu
#define STATUS_CONTROL_C_EXIT 0xC000013Au
#define STATUS_DEADLOCK 0xC0000194u

#define EXCEPTION_NONCONTINUABLE 0x01
#define EXCEPTION_UNWINDING 0x02
#define EXCEPTION_EXIT_UNWIND 0x04
#define EXCEPTION_NESTED_CALL 0x10
#define EXCEPTION_TARGET_UNWIND 0x20
#define EXCEPTION_COLLIDED_UNWIND 0x40
#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_CONTINUE_EXECUTION (-1)

#define LINUX_READ 0
#define LINUX_WRITE 1
#define LINUX_CLOSE 3
#define LINUX_FSTAT 5
#define LINUX_LSEEK 8
#define LINUX_MMAP 9
#define LINUX_MPROTECT 10
#define LINUX_MUNMAP 11
#define LINUX_RT_SIGACTION 13
#define LINUX_RT_SIGRETURN 15
#define LINUX_IOCTL 16
#define LINUX_DUP 32
#define LINUX_GETPID 39
#define LINUX_SIGALTSTACK 131
#define LINUX_FSYNC 74
#define LINUX_FTRUNCATE 77
#define LINUX_GETCWD 79
#define LINUX_CHDIR 80
#define LINUX_READLINK 89
#define LINUX_ARCH_PRCTL 158
#define LINUX_GETTID 186
#define LINUX_GETDENTS64 217
#define LINUX_CLOCK_GETTIME 228
#define LINUX_NANOSLEEP 35
#define LINUX_OPENAT 257
#define LINUX_MKDIRAT 258
#define LINUX_NEWFSTATAT 262
#define LINUX_UNLINKAT 263
#define LINUX_RENAMEAT 264
#define LINUX_GETRANDOM 318
#define APOLLO_EXIT_STATUS 1000
#define APOLLO_QUERY_MEMORY 1001

#define LINUX_AT_FDCWD (-100)
#define LINUX_ENOENT 2
#define LINUX_EEXIST 17

typedef struct {
    uint64_t home[6];
    DWORD context_flags;
    DWORD mxcsr;
    uint16_t seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss;
    DWORD eflags;
    uint64_t dr[6];
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    uint8_t fxsave[512];
    uint8_t vector_register[26 * 16];
    uint64_t vector_control, debug_control;
    uint64_t last_branch_to, last_branch_from, last_exception_to, last_exception_from;
} ALIGNED(16) CONTEXT;

typedef struct exception_record {
    DWORD code;
    DWORD flags;
    struct exception_record* record;
    void* address;
    DWORD parameter_count;
    ULONG_PTR information[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD;

typedef struct {
    EXCEPTION_RECORD* record;
    CONTEXT* context;
} EXCEPTION_POINTERS;

typedef LONG (WINAPI *top_filter_t)(EXCEPTION_POINTERS* pointers);

typedef struct {
    int64_t seconds;
    int64_t nanoseconds;
} linux_timespec_t;

typedef struct {
    uint64_t dev, ino, nlink;
    uint32_t mode, uid, gid, pad;
    uint64_t rdev;
    int64_t size, blksize, blocks;
    uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    int64_t reserved[3];
} linux_stat_t;

#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFCHR 0020000

static inline int64_t sys6(uint64_t n, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    int64_t result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}

#define sys0(n) sys6((n), 0, 0, 0, 0, 0, 0)
#define sys1(n, a) sys6((n), (uint64_t)(a), 0, 0, 0, 0, 0)
#define sys2(n, a, b) sys6((n), (uint64_t)(a), (uint64_t)(b), 0, 0, 0, 0)
#define sys3(n, a, b, c) sys6((n), (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), 0, 0, 0)
#define sys4(n, a, b, c, d) sys6((n), (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), (uint64_t)(d), 0, 0)

void* memmove(void* dest, const void* src, size_t size);
int memcmp(const void* a, const void* b, size_t size);
size_t rt_strlen(const char* s);
size_t rt_wcslen(const WCHAR* s);
int rt_strcmp(const char* a, const char* b);
bool rt_names_equal(const char* a, const char* b);
bool rt_wide_names_equal(const WCHAR* a, const char* b);
uint32_t rt_utf8_to_utf16(const char* in, uint32_t in_length, WCHAR* out, uint32_t out_size, bool* invalid);
uint32_t rt_utf16_to_utf8(const WCHAR* in, uint32_t in_length, char* out, uint32_t out_size, bool* invalid);
bool rt_path_from_wide(const WCHAR* wide, char* out, uint32_t size);
void rt_write_text(const char* text);
void rt_write_hex(uint64_t value, int digits);
DWORD rt_error_from_errno(int64_t error);
void rt_set_error_from(int64_t result);
uint64_t rt_now_ns(void);
void rt_exit(DWORD code) __attribute__((noreturn));

void rt_heap_initialize(void);
void* rt_alloc(SIZE_T size);
void* rt_alloc_zero(SIZE_T size);
void rt_free(void* block);
HANDLE rt_process_heap(void);

void rt_set_last_error(DWORD error);
DWORD rt_get_last_error(void);
uint64_t rt_image_base(void);
uint64_t rt_stack_base(void);
uint64_t rt_stack_limit(void);
void rt_run_tls_callbacks(DWORD reason);

void rt_files_initialize(void);
int64_t rt_handle_fd(HANDLE handle);
HANDLE rt_fd_handle(int64_t fd);

void rt_exceptions_initialize(void);
void rt_raise_status(DWORD code) __attribute__((noreturn));
void rt_fatal(const char* message, DWORD code) __attribute__((noreturn));

#endif
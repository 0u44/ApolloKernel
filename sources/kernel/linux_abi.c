#include "linux_abi.h"
#include "memory.h"
#include "time_keeper.h"
#include "string_utils.h"
#include "config.h"

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_STAT 4
#define SYS_FSTAT 5
#define SYS_LSTAT 6
#define SYS_POLL 7
#define SYS_LSEEK 8
#define SYS_MMAP 9
#define SYS_MPROTECT 10
#define SYS_MUNMAP 11
#define SYS_BRK 12
#define SYS_RT_SIGACTION 13
#define SYS_RT_SIGPROCMASK 14
#define SYS_RT_SIGRETURN 15
#define SYS_IOCTL 16
#define SYS_PREAD64 17
#define SYS_PWRITE64 18
#define SYS_READV 19
#define SYS_WRITEV 20
#define SYS_ACCESS 21
#define SYS_SCHED_YIELD 24
#define SYS_MREMAP 25
#define SYS_MADVISE 28
#define SYS_DUP 32
#define SYS_DUP2 33
#define SYS_NANOSLEEP 35
#define SYS_GETPID 39
#define SYS_EXIT 60
#define SYS_KILL 62
#define SYS_UNAME 63
#define SYS_FCNTL 72
#define SYS_FSYNC 74
#define SYS_FDATASYNC 75
#define SYS_FTRUNCATE 77
#define SYS_GETCWD 79
#define SYS_CHDIR 80
#define SYS_RENAME 82
#define SYS_MKDIR 83
#define SYS_RMDIR 84
#define SYS_UNLINK 87
#define SYS_READLINK 89
#define SYS_GETTIMEOFDAY 96
#define SYS_GETRLIMIT 97
#define SYS_SYSINFO 99
#define SYS_GETUID 102
#define SYS_GETGID 104
#define SYS_GETEUID 107
#define SYS_GETEGID 108
#define SYS_GETPPID 110
#define SYS_GETPGRP 111
#define SYS_SIGALTSTACK 131
#define SYS_ARCH_PRCTL 158
#define SYS_GETTID 186
#define SYS_TIME 201
#define SYS_FUTEX 202
#define SYS_SCHED_GETAFFINITY 204
#define SYS_GETDENTS64 217
#define SYS_SET_TID_ADDRESS 218
#define SYS_CLOCK_GETTIME 228
#define SYS_CLOCK_GETRES 229
#define SYS_CLOCK_NANOSLEEP 230
#define SYS_EXIT_GROUP 231
#define SYS_TGKILL 234
#define SYS_OPENAT 257
#define SYS_MKDIRAT 258
#define SYS_NEWFSTATAT 262
#define SYS_UNLINKAT 263
#define SYS_RENAMEAT 264
#define SYS_READLINKAT 267
#define SYS_FACCESSAT 269
#define SYS_PPOLL 271
#define SYS_SET_ROBUST_LIST 273
#define SYS_DUP3 292
#define SYS_PRLIMIT64 302
#define SYS_RENAMEAT2 316
#define SYS_GETRANDOM 318
#define SYS_RSEQ 334
#define SYS_FACCESSAT2 439
#define LINUX_CALL_COUNT 440
// Apollo's own calls: exit with all 32 bits of the status so PE programs keep their exit codes,
// and describe the pages at an address for VirtualQuery
#define SYS_APOLLO_EXIT_STATUS 1000
#define SYS_APOLLO_QUERY_MEMORY 1001
#define MEMORY_FREE 0
#define MEMORY_RESERVED 1
#define MEMORY_COMMITTED 2

#define PROT_WRITE 2
#define PROT_NONE 0
#define MAP_SHARED 0x01
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED_NOREPLACE 0x100000
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define MADV_DONTNEED 4
#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_COMMAND_MASK 0x7F
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME 2
#define CLOCK_THREAD_CPUTIME 3
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_REALTIME_COARSE 5
#define CLOCK_MONOTONIC_COARSE 6
#define CLOCK_BOOTTIME 7
#define CLOCK_TAI 11
#define TIMER_ABSTIME 1
#define NS_PER_SECOND 1000000000ULL
#define NS_PER_US 1000ULL
#define NS_PER_MS 1000000ULL
#define RLIMIT_STACK 3
#define RLIMIT_NOFILE 7
#define RLIM_INFINITY (~0ULL)
#define GRND_NONBLOCK 1
#define POLLIN 0x001
#define POLLOUT 0x004
#define POLLNVAL 0x020
#define POLL_MAX 64
#define UTS_LENGTH 65
#define CPU_MASK_BYTES 8
#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_FLAGS 8
#define AT_ENTRY 9
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14
#define AT_PLATFORM 15
#define AT_HWCAP 16
#define AT_CLKTCK 17
#define AT_SECURE 23
#define AT_RANDOM 25
#define AT_HWCAP2 26
#define AT_EXECFN 31
#define AUXV_ENTRIES 19
#define RANDOM_BYTES 16
#define STACK_ALIGN 16
#define EXIT_STATUS_MASK 0xFF
#define PROGRAM_UID 0
#define PARENT_PID 1
#define CPUID_FEATURES 1

typedef struct {
    int64_t seconds;
    int64_t nanoseconds;
} linux_timespec_t;

typedef struct {
    uint64_t region_base;
    uint64_t region_size;
    uint64_t run_size;
    uint32_t state;
    uint32_t writable;
} apollo_memory_info_t;

typedef struct {
    int32_t fd;
    int16_t events;
    int16_t revents;
} linux_pollfd_t;

typedef struct {
    uint64_t current;
    uint64_t maximum;
} linux_rlimit_t;

typedef struct {
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram, freeram, sharedram, bufferram, totalswap, freeswap;
    uint16_t procs, pad;
    uint32_t pad2;
    uint64_t totalhigh, freehigh;
    uint32_t mem_unit;
    char reserved[4];
} linux_sysinfo_t;

static const char* const environment[] = {"HOME=/home", "PATH=/bin:/boot", "TERM=dumb", "USER=apollo"};

static uint64_t start_ns;
static uint64_t idle_ns;
static uint64_t epoch_ns;
static uint64_t fs_base;
static uint64_t gs_base;

void linux_reset(void) {
    linux_signals_reset();
    linux_files_reset();
    start_ns = time_keeper_get_uptime_ns();
    idle_ns = 0;
    epoch_ns = time_keeper_get_unix_time() * NS_PER_SECOND - start_ns;
    fs_base = gs_base = 0;
}

/* startup stack */

static bool push_bytes(uint64_t* sp, const void* data, uint64_t length) {
    *sp -= length;
    return user_copy_out(*sp, data, length);
}

static bool push_word(uint64_t* sp, uint64_t value) {
    return push_bytes(sp, &value, sizeof(value));
}

static uint64_t cpu_features(void) {
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(CPUID_FEATURES), "c"(0));
    return d;
}

// Strings go at the top, then auxv, envp, argv and argc so rsp points at argc 16 byte aligned
uint64_t linux_build_stack(uint64_t phdr, uint32_t phnum, uint32_t phent) {
    uint64_t sp = USER_STACK_TOP;
    uint64_t argv_at[PROGRAM_MAX_ARGS];
    uint64_t env_at[ARRAY_SIZE(environment)];
    uint8_t random[RANDOM_BYTES];
    program_random(random, sizeof(random));
    bool ok = push_bytes(&sp, "x86_64", sizeof("x86_64"));
    uint64_t platform = sp;
    ok = ok && push_bytes(&sp, random, sizeof(random));
    uint64_t random_at = sp;
    ok = ok && push_bytes(&sp, program.path, string_length(program.path) + 1);
    uint64_t execfn = sp;
    for (int i = program.argc - 1; ok && i >= 0; i--) {
        ok = push_bytes(&sp, program.argv[i], string_length(program.argv[i]) + 1);
        argv_at[i] = sp;
    }
    for (int i = (int)ARRAY_SIZE(environment) - 1; ok && i >= 0; i--) {
        ok = push_bytes(&sp, environment[i], string_length(environment[i]) + 1);
        env_at[i] = sp;
    }
    uint64_t words = 1 + program.argc + 1 + ARRAY_SIZE(environment) + 1 + AUXV_ENTRIES * 2;
    sp = ALIGN_DOWN(sp, STACK_ALIGN);
    if (words % 2) sp -= sizeof(uint64_t);
    uint64_t auxv[AUXV_ENTRIES * 2] = {
        AT_PHDR, phdr, AT_PHENT, phent, AT_PHNUM, phnum, AT_PAGESZ, PAGE_SIZE, AT_BASE, 0,
        AT_FLAGS, 0, AT_ENTRY, program.entry, AT_UID, PROGRAM_UID, AT_EUID, PROGRAM_UID,
        AT_GID, PROGRAM_UID, AT_EGID, PROGRAM_UID, AT_PLATFORM, platform, AT_HWCAP, cpu_features(),
        AT_CLKTCK, TIMER_HZ, AT_SECURE, 0, AT_RANDOM, random_at, AT_HWCAP2, 0, AT_EXECFN, execfn,
        AT_NULL, 0
    };
    ok = ok && push_bytes(&sp, auxv, sizeof(auxv));
    ok = ok && push_word(&sp, 0);
    for (int i = (int)ARRAY_SIZE(environment) - 1; ok && i >= 0; i--) ok = push_word(&sp, env_at[i]);
    ok = ok && push_word(&sp, 0);
    for (int i = program.argc - 1; ok && i >= 0; i--) ok = push_word(&sp, argv_at[i]);
    ok = ok && push_word(&sp, (uint64_t)program.argc);
    return ok ? sp : 0;
}

/* memory */

static int64_t sys_brk(interrupt_frame_t* f) {
    uint64_t target = ARG0(f);
    if (target < program.brk_start) return (int64_t)program.brk_end;
    uint64_t old_top = ALIGN_UP(program.brk_end, PAGE_SIZE);
    uint64_t new_top = ALIGN_UP(target, PAGE_SIZE);
    if (new_top > old_top) {
        if (!address_space_is_user(old_top, new_top - old_top) || !program_range_free(old_top, new_top - old_top)) {
            return (int64_t)program.brk_end;
        }
        if (!program_map(old_top, new_top - old_top, PROGRAM_MAP_COMMIT | PROGRAM_MAP_WRITE, true)) {
            return (int64_t)program.brk_end;
        }
    } else if (new_top < old_top) {
        program_unmap(new_top, old_top - new_top);
    }
    program.brk_end = target;
    return (int64_t)target;
}

static int64_t map_file(uint64_t address, uint64_t length, uint64_t prot, int64_t fd, uint64_t offset) {
    if (!user_check(address, length, true)) return -ENOMEM;
    int64_t n = linux_file_read_at(fd, address, length, offset);
    if (n < 0) {
        program_unmap(address, length);
        return n;
    }
    if (!(prot & PROT_WRITE)) address_space_protect(&program.as, address, length, false);
    return (int64_t)address;
}

// PROT_NONE only reserves, so large reservations do not take memory until mprotect opens them
static int64_t sys_mmap(interrupt_frame_t* f) {
    uint64_t address = ARG0(f), length = ARG1(f), prot = ARG2(f), flags = ARG3(f), offset = ARG5(f);
    int64_t fd = (int64_t)ARG4(f);
    bool anonymous = flags & MAP_ANONYMOUS;
    if (length == 0 || offset % PAGE_SIZE) return -EINVAL;
    if (!anonymous && !program_fd_get(fd)) return -EBADF;
    if (!anonymous && (flags & MAP_SHARED) && (prot & PROT_WRITE)) return -ENODEV;
    if ((flags & MAP_FIXED_NOREPLACE) && !program_range_free(address, ALIGN_UP(length, PAGE_SIZE))) return -EEXIST;
    bool fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE);
    uint32_t map_flags = prot == PROT_NONE ? 0 : PROGRAM_MAP_COMMIT;
    // File contents are copied in through the mapping, it starts writable and loses that afterwards
    if ((prot & PROT_WRITE) || (!anonymous && prot != PROT_NONE)) map_flags |= PROGRAM_MAP_WRITE;
    uint64_t mapped = program_map(address, length, map_flags, fixed);
    if (!mapped) return -ENOMEM;
    if (anonymous || prot == PROT_NONE) return (int64_t)mapped;
    return map_file(mapped, length, prot, fd, offset);
}

static int64_t sys_munmap(interrupt_frame_t* f) {
    if (ARG0(f) % PAGE_SIZE || ARG1(f) == 0) return -EINVAL;
    return program_unmap(ARG0(f), ARG1(f)) ? 0 : -EINVAL;
}

// Without NX and with no way to revoke reads, PROT_NONE on mapped pages leaves them readable
static int64_t sys_mprotect(interrupt_frame_t* f) {
    uint64_t address = ARG0(f), length = ALIGN_UP(ARG1(f), PAGE_SIZE), prot = ARG2(f);
    if (address % PAGE_SIZE) return -EINVAL;
    if (length == 0) return 0;
    if (prot == PROT_NONE) {
        address_space_protect(&program.as, address, length, false);
        return 0;
    }
    return program_commit(address, length, prot & PROT_WRITE) ? 0 : -ENOMEM;
}

static int64_t sys_mremap(interrupt_frame_t* f) {
    uint64_t old = ARG0(f), old_length = ALIGN_UP(ARG1(f), PAGE_SIZE), new_length = ALIGN_UP(ARG2(f), PAGE_SIZE);
    if (old % PAGE_SIZE || new_length == 0 || (ARG3(f) & MREMAP_FIXED)) return -EINVAL;
    if (new_length <= old_length) {
        if (new_length < old_length) program_unmap(old + new_length, old_length - new_length);
        return (int64_t)old;
    }
    uint64_t extra = new_length - old_length;
    if (program_range_free(old + old_length, extra) &&
        program_map(old + old_length, extra, PROGRAM_MAP_COMMIT | PROGRAM_MAP_WRITE, true)) {
        return (int64_t)old;
    }
    if (!(ARG3(f) & MREMAP_MAYMOVE)) return -ENOMEM;
    uint64_t moved = program_map(0, new_length, PROGRAM_MAP_COMMIT | PROGRAM_MAP_WRITE, false);
    if (!moved) return -ENOMEM;
    if (!user_check(old, old_length, false)) {
        program_unmap(moved, new_length);
        return -EFAULT;
    }
    memcpy((void*)(uintptr_t)moved, (const void*)(uintptr_t)old, old_length);
    program_unmap(old, old_length);
    return (int64_t)moved;
}

static int64_t sys_madvise(interrupt_frame_t* f) {
    if (ARG0(f) % PAGE_SIZE) return -EINVAL;
    if (ARG2(f) != MADV_DONTNEED) return 0;
    // Anonymous pages read back as zeros after MADV_DONTNEED
    if (!user_check(ARG0(f), ARG1(f), true)) return -ENOMEM;
    memset((void*)(uintptr_t)ARG0(f), 0, ARG1(f));
    return 0;
}

/* time */

static uint64_t clock_now(uint64_t clock) {
    uint64_t now = time_keeper_get_uptime_ns();
    switch (clock) {
        case CLOCK_REALTIME: case CLOCK_REALTIME_COARSE: case CLOCK_TAI: return epoch_ns + now;
        case CLOCK_PROCESS_CPUTIME: case CLOCK_THREAD_CPUTIME: return now - start_ns - idle_ns;
        default: return now;
    }
}

static bool valid_clock(uint64_t clock) {
    return clock <= CLOCK_BOOTTIME || clock == CLOCK_TAI;
}

static int64_t write_timespec(uint64_t user, uint64_t ns) {
    linux_timespec_t ts = {(int64_t)(ns / NS_PER_SECOND), (int64_t)(ns % NS_PER_SECOND)};
    return user_copy_out(user, &ts, sizeof(ts)) ? 0 : -EFAULT;
}

static int64_t sys_clock_gettime(interrupt_frame_t* f) {
    if (!valid_clock(ARG0(f))) return -EINVAL;
    return write_timespec(ARG1(f), clock_now(ARG0(f)));
}

static int64_t sys_clock_getres(interrupt_frame_t* f) {
    if (!valid_clock(ARG0(f))) return -EINVAL;
    return ARG1(f) ? write_timespec(ARG1(f), 1) : 0;
}

static int64_t sys_gettimeofday(interrupt_frame_t* f) {
    uint64_t now = clock_now(CLOCK_REALTIME);
    int64_t tv[2] = {(int64_t)(now / NS_PER_SECOND), (int64_t)((now % NS_PER_SECOND) / NS_PER_US)};
    if (ARG0(f) && !user_copy_out(ARG0(f), tv, sizeof(tv))) return -EFAULT;
    if (ARG1(f)) {
        int32_t zone[2] = {0, 0};
        if (!user_copy_out(ARG1(f), zone, sizeof(zone))) return -EFAULT;
    }
    return 0;
}

static int64_t sys_time(interrupt_frame_t* f) {
    int64_t seconds = (int64_t)(clock_now(CLOCK_REALTIME) / NS_PER_SECOND);
    if (ARG0(f) && !user_copy_out(ARG0(f), &seconds, sizeof(seconds))) return -EFAULT;
    return seconds;
}

// Waits with the keyboard polled, a signal that arrives ends the wait early
static bool wait_until(uint64_t deadline_ns) {
    uint64_t began = time_keeper_get_uptime_ns();
    bool completed = true;
    while (time_keeper_get_uptime_ns() < deadline_ns) {
        console_poll_keyboard();
        if (linux_signal_waiting()) { completed = false; break; }
        __asm__ volatile("pause");
    }
    idle_ns += time_keeper_get_uptime_ns() - began;
    return completed;
}

static int64_t sleep_for(uint64_t clock, uint64_t flags, uint64_t request, uint64_t remain) {
    linux_timespec_t ts;
    if (!user_copy_in(&ts, request, sizeof(ts))) return -EFAULT;
    if (ts.seconds < 0 || ts.nanoseconds < 0 || (uint64_t)ts.nanoseconds >= NS_PER_SECOND) return -EINVAL;
    uint64_t amount = (uint64_t)ts.seconds * NS_PER_SECOND + (uint64_t)ts.nanoseconds;
    uint64_t now = time_keeper_get_uptime_ns();
    uint64_t deadline = (flags & TIMER_ABSTIME) ? now + (amount > clock_now(clock) ? amount - clock_now(clock) : 0) : now + amount;
    if (wait_until(deadline)) return 0;
    if (remain && !(flags & TIMER_ABSTIME)) write_timespec(remain, deadline - time_keeper_get_uptime_ns());
    return -EINTR;
}

static int64_t sys_nanosleep(interrupt_frame_t* f) {
    return sleep_for(CLOCK_MONOTONIC, 0, ARG0(f), ARG1(f));
}

static int64_t sys_clock_nanosleep(interrupt_frame_t* f) {
    if (!valid_clock(ARG0(f))) return -EINVAL;
    return sleep_for(ARG0(f), ARG1(f), ARG2(f), ARG3(f));
}

/* polling */

static int16_t poll_ready(const linux_pollfd_t* p) {
    program_file_t* file = program_fd_get(p->fd);
    if (!file) return POLLNVAL;
    if (file->type == HANDLE_CONSOLE_IN) return console_pending() ? (p->events & POLLIN) : 0;
    if (file->type == HANDLE_CONSOLE_OUT) return p->events & POLLOUT;
    return p->events & (POLLIN | POLLOUT);
}

static int64_t poll_files(uint64_t user, uint64_t count, int64_t timeout_ms) {
    linux_pollfd_t fds[POLL_MAX];
    if (count > POLL_MAX) return -EINVAL;
    if (!user_copy_in(fds, user, count * sizeof(linux_pollfd_t))) return -EFAULT;
    uint64_t began = time_keeper_get_uptime_ns();
    uint64_t deadline = timeout_ms < 0 ? ~0ULL : began + (uint64_t)timeout_ms * NS_PER_MS;
    int64_t ready = 0;
    while (true) {
        ready = 0;
        for (uint64_t i = 0; i < count; i++) {
            fds[i].revents = fds[i].fd < 0 ? 0 : poll_ready(&fds[i]);
            if (fds[i].revents) ready++;
        }
        if (ready || time_keeper_get_uptime_ns() >= deadline) break;
        if (linux_signal_waiting()) { ready = -EINTR; break; }
        __asm__ volatile("pause");
    }
    idle_ns += time_keeper_get_uptime_ns() - began;
    if (ready >= 0 && !user_copy_out(user, fds, count * sizeof(linux_pollfd_t))) return -EFAULT;
    return ready;
}

static int64_t sys_poll(interrupt_frame_t* f) {
    return poll_files(ARG0(f), ARG1(f), (int32_t)ARG2(f));
}

static int64_t sys_ppoll(interrupt_frame_t* f) {
    int64_t timeout = -1;
    if (ARG2(f)) {
        linux_timespec_t ts;
        if (!user_copy_in(&ts, ARG2(f), sizeof(ts))) return -EFAULT;
        timeout = ts.seconds * (int64_t)(NS_PER_SECOND / NS_PER_MS) + ts.nanoseconds / (int64_t)NS_PER_MS;
    }
    return poll_files(ARG0(f), ARG1(f), timeout);
}

/* process */

static int64_t sys_exit(interrupt_frame_t* f) {
    program_exit((int64_t)(ARG0(f) & EXIT_STATUS_MASK));
}

static int64_t sys_getpid(interrupt_frame_t* f) {
    (void)f;
    return program.pid;
}

static int64_t sys_getppid(interrupt_frame_t* f) {
    (void)f;
    return PARENT_PID;
}

static int64_t sys_getuid(interrupt_frame_t* f) {
    (void)f;
    return PROGRAM_UID;
}

static int64_t sys_succeed(interrupt_frame_t* f) {
    (void)f;
    return 0;
}

static int64_t sys_not_supported(interrupt_frame_t* f) {
    (void)f;
    return -ENOSYS;
}

static int64_t sys_arch_prctl(interrupt_frame_t* f) {
    switch (ARG0(f)) {
        case ARCH_SET_FS: fs_base = ARG1(f); cpu_set_fs_base(fs_base); return 0;
        case ARCH_SET_GS: gs_base = ARG1(f); cpu_set_gs_base(gs_base); return 0;
        case ARCH_GET_FS: return user_copy_out(ARG1(f), &fs_base, sizeof(fs_base)) ? 0 : -EFAULT;
        case ARCH_GET_GS: return user_copy_out(ARG1(f), &gs_base, sizeof(gs_base)) ? 0 : -EFAULT;
        default: return -EINVAL;
    }
}

// One thread exists, so a wait on a matching value could never be woken
static int64_t sys_futex(interrupt_frame_t* f) {
    uint32_t command = (uint32_t)ARG1(f) & FUTEX_COMMAND_MASK;
    if (command == FUTEX_WAKE || command == FUTEX_WAKE_BITSET) return 0;
    if (command != FUTEX_WAIT && command != FUTEX_WAIT_BITSET) return -ENOSYS;
    uint32_t value;
    if (!user_copy_in(&value, ARG0(f), sizeof(value))) return -EFAULT;
    if (value != (uint32_t)ARG2(f)) return -EAGAIN;
    if (!ARG3(f)) program_kill("Deadlock: futex wait with no other thread to wake it", EXIT_STATUS_MASK);
    return sleep_for(command == FUTEX_WAIT ? CLOCK_MONOTONIC : CLOCK_REALTIME,
                     command == FUTEX_WAIT ? 0 : TIMER_ABSTIME, ARG3(f), 0) == 0 ? -ETIMEDOUT : -EINTR;
}

static void limit_for(uint64_t resource, linux_rlimit_t* limit) {
    limit->current = limit->maximum = RLIM_INFINITY;
    if (resource == RLIMIT_STACK) limit->current = limit->maximum = USER_STACK_RESERVE;
    if (resource == RLIMIT_NOFILE) limit->current = limit->maximum = PROGRAM_MAX_HANDLES;
}

// Limits are fixed, a request to change one is refused
static int64_t sys_prlimit64(interrupt_frame_t* f) {
    if (ARG0(f) != 0 && ARG0(f) != program.pid) return -ESRCH;
    if (ARG2(f)) return -EPERM;
    linux_rlimit_t limit;
    limit_for(ARG1(f), &limit);
    return !ARG3(f) || user_copy_out(ARG3(f), &limit, sizeof(limit)) ? 0 : -EFAULT;
}

static int64_t sys_getrlimit(interrupt_frame_t* f) {
    linux_rlimit_t limit;
    limit_for(ARG0(f), &limit);
    return user_copy_out(ARG1(f), &limit, sizeof(limit)) ? 0 : -EFAULT;
}

static void copy_field(char* field, const char* text) {
    string_copy_n(field, text, UTS_LENGTH);
}

static int64_t sys_uname(interrupt_frame_t* f) {
    char uts[UTS_LENGTH * 6];
    memset(uts, 0, sizeof(uts));
    copy_field(uts, "Apollo");
    copy_field(uts + UTS_LENGTH, "apollo");
    copy_field(uts + UTS_LENGTH * 2, APOLLO_VERSION_STRING);
    copy_field(uts + UTS_LENGTH * 3, __DATE__ " " __TIME__);
    copy_field(uts + UTS_LENGTH * 4, "x86_64");
    return user_copy_out(ARG0(f), uts, sizeof(uts)) ? 0 : -EFAULT;
}

static int64_t sys_getrandom(interrupt_frame_t* f) {
    if (!user_check(ARG0(f), ARG1(f), true)) return -EFAULT;
    program_random((uint8_t*)(uintptr_t)ARG0(f), ARG1(f));
    return (int64_t)ARG1(f);
}

static int64_t sys_sched_getaffinity(interrupt_frame_t* f) {
    uint64_t mask = 1;
    if (ARG1(f) < CPU_MASK_BYTES) return -EINVAL;
    return user_copy_out(ARG2(f), &mask, sizeof(mask)) ? CPU_MASK_BYTES : -EFAULT;
}

static int64_t sys_sysinfo(interrupt_frame_t* f) {
    linux_sysinfo_t info;
    memset(&info, 0, sizeof(info));
    info.uptime = (int64_t)time_keeper_get_uptime_seconds();
    info.totalram = memory_total_frames();
    info.freeram = memory_free_frames();
    info.procs = 1;
    info.mem_unit = PAGE_SIZE;
    return user_copy_out(ARG0(f), &info, sizeof(info)) ? 0 : -EFAULT;
}

static uint32_t page_state(uint64_t page, bool* writable) {
    *writable = address_space_is_mapped(&program.as, page, true);
    if (address_space_is_mapped(&program.as, page, false)) return MEMORY_COMMITTED;
    return program_region_at(page) ? MEMORY_RESERVED : MEMORY_FREE;
}

// The run covers pages from the address on that share state and protection, inside one region
static int64_t sys_apollo_query_memory(interrupt_frame_t* f) {
    apollo_memory_info_t info;
    memset(&info, 0, sizeof(info));
    uint64_t page = ALIGN_DOWN(ARG0(f), PAGE_SIZE);
    const program_region_t* region = program_region_at(page);
    bool writable;
    info.state = page_state(page, &writable);
    info.writable = writable;
    if (region) {
        info.region_base = region->start;
        info.region_size = region->length;
        uint64_t end = region->start + region->length;
        uint64_t next = page;
        bool next_writable;
        while (next < end && page_state(next, &next_writable) == info.state && next_writable == writable) next += PAGE_SIZE;
        info.run_size = next - page;
    }
    return user_copy_out(ARG1(f), &info, sizeof(info)) ? 0 : -EFAULT;
}

/* dispatch */

static const linux_call_t calls[LINUX_CALL_COUNT] = {
    [SYS_READ] = linux_read, [SYS_WRITE] = linux_write, [SYS_OPEN] = linux_open, [SYS_CLOSE] = linux_close,
    [SYS_STAT] = linux_stat, [SYS_FSTAT] = linux_fstat, [SYS_LSTAT] = linux_stat, [SYS_POLL] = sys_poll,
    [SYS_LSEEK] = linux_lseek, [SYS_MMAP] = sys_mmap, [SYS_MPROTECT] = sys_mprotect, [SYS_MUNMAP] = sys_munmap,
    [SYS_BRK] = sys_brk, [SYS_RT_SIGACTION] = linux_rt_sigaction, [SYS_RT_SIGPROCMASK] = linux_rt_sigprocmask,
    [SYS_RT_SIGRETURN] = linux_rt_sigreturn, [SYS_IOCTL] = linux_ioctl, [SYS_PREAD64] = linux_pread,
    [SYS_PWRITE64] = linux_pwrite, [SYS_READV] = linux_readv, [SYS_WRITEV] = linux_writev,
    [SYS_ACCESS] = linux_access, [SYS_SCHED_YIELD] = sys_succeed, [SYS_MREMAP] = sys_mremap,
    [SYS_MADVISE] = sys_madvise, [SYS_DUP] = linux_dup, [SYS_DUP2] = linux_dup2, [SYS_NANOSLEEP] = sys_nanosleep,
    [SYS_GETPID] = sys_getpid, [SYS_EXIT] = sys_exit, [SYS_KILL] = linux_kill, [SYS_UNAME] = sys_uname,
    [SYS_FCNTL] = linux_fcntl, [SYS_FSYNC] = linux_fsync, [SYS_FDATASYNC] = linux_fsync,
    [SYS_FTRUNCATE] = linux_ftruncate, [SYS_GETCWD] = linux_getcwd, [SYS_CHDIR] = linux_chdir,
    [SYS_RENAME] = linux_rename, [SYS_MKDIR] = linux_mkdir, [SYS_RMDIR] = linux_rmdir, [SYS_UNLINK] = linux_unlink,
    [SYS_READLINK] = linux_readlink, [SYS_GETTIMEOFDAY] = sys_gettimeofday, [SYS_GETRLIMIT] = sys_getrlimit,
    [SYS_SYSINFO] = sys_sysinfo, [SYS_GETUID] = sys_getuid, [SYS_GETGID] = sys_getuid, [SYS_GETEUID] = sys_getuid,
    [SYS_GETEGID] = sys_getuid, [SYS_GETPPID] = sys_getppid, [SYS_GETPGRP] = sys_getpid,
    [SYS_SIGALTSTACK] = linux_sigaltstack, [SYS_ARCH_PRCTL] = sys_arch_prctl, [SYS_GETTID] = sys_getpid,
    [SYS_TIME] = sys_time, [SYS_FUTEX] = sys_futex, [SYS_SCHED_GETAFFINITY] = sys_sched_getaffinity,
    [SYS_GETDENTS64] = linux_getdents64, [SYS_SET_TID_ADDRESS] = sys_getpid, [SYS_CLOCK_GETTIME] = sys_clock_gettime,
    [SYS_CLOCK_GETRES] = sys_clock_getres, [SYS_CLOCK_NANOSLEEP] = sys_clock_nanosleep, [SYS_EXIT_GROUP] = sys_exit,
    [SYS_TGKILL] = linux_tgkill, [SYS_OPENAT] = linux_openat, [SYS_MKDIRAT] = linux_mkdirat,
    [SYS_NEWFSTATAT] = linux_newfstatat, [SYS_UNLINKAT] = linux_unlinkat, [SYS_RENAMEAT] = linux_renameat,
    [SYS_READLINKAT] = linux_readlinkat, [SYS_FACCESSAT] = linux_faccessat, [SYS_PPOLL] = sys_ppoll,
    [SYS_SET_ROBUST_LIST] = sys_succeed, [SYS_DUP3] = linux_dup3, [SYS_PRLIMIT64] = sys_prlimit64,
    [SYS_RENAMEAT2] = linux_renameat, [SYS_GETRANDOM] = sys_getrandom, [SYS_RSEQ] = sys_not_supported,
    [SYS_FACCESSAT2] = linux_faccessat,
};

void linux_syscall(interrupt_frame_t* frame) {
    uint64_t call = frame->rax;
    if (call == SYS_APOLLO_EXIT_STATUS) program_exit((int64_t)(uint32_t)ARG0(frame));
    if (call == SYS_APOLLO_QUERY_MEMORY) {
        frame->rax = (uint64_t)sys_apollo_query_memory(frame);
        return;
    }
    linux_call_t handler = call < LINUX_CALL_COUNT ? calls[call] : NULL;
    int64_t result = handler ? handler(frame) : -ENOSYS;
    frame->rax = (uint64_t)result;
    // rt_sigreturn put back a whole register set, its rax is not a call result
    linux_deliver_pending(frame, call == SYS_RT_SIGRETURN ? (uint64_t)-1 : call, call == SYS_RT_SIGRETURN ? 0 : result);
}
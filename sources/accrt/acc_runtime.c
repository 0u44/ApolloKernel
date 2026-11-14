#include "acc_runtime.h"
#include "acc_bytecode.h"

#define LINUX_READ 0
#define LINUX_WRITE 1
#define LINUX_CLOSE 3
#define LINUX_IOCTL 16
#define LINUX_OPENAT 257
#define APOLLO_EXIT_STATUS 1000
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0x40
#define O_TRUNC 0x200
#define O_APPEND 0x400
#define FILE_MODE 0644
#define TCGETS 0x5401
#define TCSETS 0x5402
#define TERMIOS_SIZE 36
#define TERMIOS_LFLAG 12
#define TERMIOS_ICANON 0x2
#define TERMIOS_ECHO 0x8
#define STDIN 0
#define STDOUT 1
#define STDERR 2
#define MAX_FILES 4
#define FILE_HANDLE_BASE 1
#define MAX_ARGS 16
#define SINK_SIZE 128
#define EXIT_RUNTIME_ERROR 1

typedef struct {
    int64_t fd;
    char buffer[SINK_SIZE];
    uint32_t used;
} sink_t;

extern char _start[];
extern char __runtime_end[];
int32_t acc_sys(uint64_t id, uint64_t argc, const int64_t* top, uint64_t offset);
void acc_trap(uint64_t offset, uint64_t reason) __attribute__((noreturn));

__attribute__((section(".runtime_header"), used))
acc_runtime_header_t acc_header = {
    ACC_RUNTIME_MAGIC, 0, (uint64_t)_start, (uint64_t)acc_sys, (uint64_t)acc_trap, (uint64_t)__runtime_end, 0, 0, 0
};

static int64_t files[MAX_FILES];
static uint64_t current_offset;

static inline int64_t sys4(uint64_t n, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    register uint64_t r10 __asm__("r10") = d;
    int64_t result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return result;
}

__asm__(
    ".text\n"
    ".globl _start\n"
    "_start:\n"
    "    and $-16, %rsp\n"
    "    mov acc_header+40(%rip), %rax\n"
    "    call *%rax\n"
    "    ud2\n");

static uint32_t length_of(const char* s) {
    uint32_t n = 0;
    while (s[n]) n++;
    return n;
}

static void write_all(int64_t fd, const char* text, uint32_t length) {
    sys4(LINUX_WRITE, (uint64_t)fd, (uint64_t)text, length, 0);
}

static void exit_with(int32_t code) __attribute__((noreturn));
static void exit_with(int32_t code) {
    for (;;) sys4(APOLLO_EXIT_STATUS, (uint32_t)code, 0, 0, 0);
}

/* runtime errors, worded the way the bytecode executor words them */

static void fail(const char* message) __attribute__((noreturn));
static void fail(const char* message) {
    const char hex[] = "0123456789abcdef";
    char where[5];
    for (int i = 0; i < 4; i++) where[i] = hex[(current_offset >> (12 - 4 * i)) & 0xF];
    where[4] = '\0';
    write_all(STDERR, "Execution failed: runtime error at 0x", 37);
    write_all(STDERR, where, 4);
    write_all(STDERR, ": ", 2);
    write_all(STDERR, message, length_of(message));
    write_all(STDERR, "\n", 1);
    exit_with(EXIT_RUNTIME_ERROR);
}

void acc_trap(uint64_t offset, uint64_t reason) {
    current_offset = offset;
    fail(reason == ACC_TRAP_DIVIDE ? "division by zero" : "array index out of bounds");
}

static const char* string_at(int32_t value) {
    uint32_t offset = (uint32_t)value & ACC_STRING_MASK;
    if (!((uint32_t)value & ACC_STRING_TAG) || offset >= acc_header.data_size) fail("value is not a string");
    return (const char*)(acc_header.data + offset);
}

static int64_t file_at(int32_t handle) {
    int32_t index = handle - FILE_HANDLE_BASE;
    if (index < 0 || index >= MAX_FILES || !files[index]) fail("invalid FILE handle");
    return files[index];
}

/* formatted output */

static void sink_flush(sink_t* sink) {
    if (sink->used) write_all(sink->fd, sink->buffer, sink->used);
    sink->used = 0;
}

static void sink_put(sink_t* sink, char c) {
    if (sink->used == SINK_SIZE) sink_flush(sink);
    sink->buffer[sink->used++] = c;
}

static void sink_text(sink_t* sink, const char* text, uint32_t width, bool left) {
    uint32_t len = length_of(text);
    for (uint32_t i = len; !left && i < width; i++) sink_put(sink, ' ');
    for (uint32_t i = 0; i < len; i++) sink_put(sink, text[i]);
    for (uint32_t i = len; left && i < width; i++) sink_put(sink, ' ');
}

static void sink_number(sink_t* sink, uint32_t value, bool negative, uint32_t base, bool upper,
                        uint32_t width, bool left, bool zero) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char text[12];
    uint32_t n = 0;
    do { text[n++] = digits[value % base]; value /= base; } while (value);
    uint32_t len = n + (negative ? 1 : 0);
    if (negative && zero) sink_put(sink, '-');
    for (uint32_t i = len; !left && i < width; i++) sink_put(sink, zero ? '0' : ' ');
    if (negative && !zero) sink_put(sink, '-');
    while (n > 0) sink_put(sink, text[--n]);
    for (uint32_t i = len; left && i < width; i++) sink_put(sink, ' ');
}

static void conversion(sink_t* sink, char kind, int32_t arg, uint32_t width, bool left, bool zero) {
    switch (kind) {
        case 'd': case 'i': sink_number(sink, arg < 0 ? (uint32_t)-arg : (uint32_t)arg, arg < 0, 10, false, width, left, zero); break;
        case 'u': sink_number(sink, (uint32_t)arg, false, 10, false, width, left, zero); break;
        case 'x': case 'X': sink_number(sink, (uint32_t)arg, false, 16, kind == 'X', width, left, zero); break;
        case 'c': { char c[2] = {(char)arg, '\0'}; sink_text(sink, c, width, left); break; }
        case 's': sink_text(sink, string_at(arg), width, left); break;
        default: sink_flush(sink); fail("unsupported printf conversion");
    }
}

static void format(int64_t fd, const char* fmt, const int32_t* args, uint32_t argc) {
    sink_t sink = {fd, {0}, 0};
    uint32_t next = 0;
    for (const char* p = fmt; *p; p++) {
        if (*p != '%') { sink_put(&sink, *p); continue; }
        p++;
        bool left = false, zero = false;
        while (*p == '-' || *p == '0') { if (*p == '-') left = true; else zero = true; p++; }
        uint32_t width = 0;
        while (*p >= '0' && *p <= '9') width = width * 10 + (uint32_t)(*p++ - '0');
        if (*p == '%') { sink_put(&sink, '%'); continue; }
        if (next >= argc) { sink_flush(&sink); fail("printf has fewer arguments than conversions"); }
        conversion(&sink, *p, args[next++], width, left, zero);
    }
    sink_flush(&sink);
}

static int32_t put_string(int64_t fd, int32_t text, bool newline) {
    sink_t sink = {fd, {0}, 0};
    sink_text(&sink, string_at(text), 0, false);
    if (newline) sink_put(&sink, '\n');
    sink_flush(&sink);
    return 0;
}

/* builtins */

// Keys come one at a time without echo, as the bytecode executor reads them
static int32_t get_char(void) {
    uint8_t saved[TERMIOS_SIZE], raw[TERMIOS_SIZE];
    sys4(LINUX_IOCTL, STDIN, TCGETS, (uint64_t)saved, 0);
    for (int i = 0; i < TERMIOS_SIZE; i++) raw[i] = saved[i];
    *(uint32_t*)(raw + TERMIOS_LFLAG) &= ~(uint32_t)(TERMIOS_ICANON | TERMIOS_ECHO);
    sys4(LINUX_IOCTL, STDIN, TCSETS, (uint64_t)raw, 0);
    char c = 0;
    while (sys4(LINUX_READ, STDIN, (uint64_t)&c, 1, 0) != 1) {}
    sys4(LINUX_IOCTL, STDIN, TCSETS, (uint64_t)saved, 0);
    return c == '\r' ? '\n' : (uint8_t)c;
}

static int32_t open_file(int32_t path_value, int32_t mode_value) {
    const char* path = string_at(path_value);
    const char* mode = string_at(mode_value);
    int32_t slot = -1;
    for (int32_t i = 0; i < MAX_FILES; i++) if (!files[i]) { slot = i; break; }
    if (slot < 0) return 0;
    uint64_t flags = mode[0] == 'w' ? (O_WRONLY | O_CREAT | O_TRUNC) : mode[0] == 'a' ? (O_WRONLY | O_CREAT | O_APPEND) : O_RDONLY;
    int64_t fd = sys4(LINUX_OPENAT, (uint64_t)AT_FDCWD, (uint64_t)path, flags, FILE_MODE);
    if (fd < 0) return 0;
    files[slot] = fd;
    return slot + FILE_HANDLE_BASE;
}

static int32_t close_file(int32_t handle) {
    sys4(LINUX_CLOSE, (uint64_t)file_at(handle), 0, 0, 0);
    files[handle - FILE_HANDLE_BASE] = 0;
    return 0;
}

static int32_t run_builtin(uint64_t id, const int32_t* args, uint32_t argc) {
    switch (id) {
        case SYS_PRINTF: format(STDOUT, string_at(args[0]), args + 1, argc - 1); return 0;
        case SYS_FPRINTF: format(file_at(args[0]), string_at(args[1]), args + 2, argc - 2); return 0;
        case SYS_PUTCHAR: { char c = (char)args[0]; write_all(STDOUT, &c, 1); return args[0]; }
        case SYS_PUTS: return put_string(STDOUT, args[0], true);
        case SYS_FPUTS: return put_string(file_at(args[1]), args[0], false);
        case SYS_GETCHAR: return get_char();
        case SYS_EXIT: exit_with(args[0]);
        case SYS_FOPEN: return open_file(args[0], args[1]);
        case SYS_FCLOSE: return close_file(args[0]);
        default: fail("unknown builtin");
    }
}

// Arguments sit on the program's stack with the last one on top, they are put back in source order
int32_t acc_sys(uint64_t id, uint64_t argc, const int64_t* top, uint64_t offset) {
    int32_t args[MAX_ARGS];
    current_offset = offset;
    if (argc > MAX_ARGS) fail("too many builtin arguments");
    for (uint64_t i = 0; i < argc; i++) args[i] = (int32_t)top[argc - 1 - i];
    return run_builtin(id, args, (uint32_t)argc);
}
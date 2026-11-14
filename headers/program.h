#ifndef APOLLO_PROGRAM_H
#define APOLLO_PROGRAM_H

#include "types.h"
#include "cpu.h"
#include "address_space.h"
#include "filesystem.h"

#define PROGRAM_MAX_ARGS 16
#define PROGRAM_ARG_LENGTH 128
#define PROGRAM_MAX_HANDLES 32
#define PROGRAM_MAX_REGIONS 512
#define PROGRAM_ERROR_LENGTH 160

#define USER_STACK_TOP 0x00007FFFFFFFE000ULL
#define USER_STACK_RESERVE (8ULL * 1024 * 1024)
#define USER_STACK_COMMIT (256ULL * 1024)
#define USER_MMAP_BASE 0x0000100000000000ULL
#define USER_MMAP_END 0x0000700000000000ULL

typedef enum {
    PROGRAM_FORMAT_UNKNOWN,
    PROGRAM_FORMAT_ACC,
    PROGRAM_FORMAT_ELF,
    PROGRAM_FORMAT_PE,
    PROGRAM_FORMAT_BIN
} program_format_t;

typedef enum {
    HANDLE_FREE,
    HANDLE_CONSOLE_IN,
    HANDLE_CONSOLE_OUT,
    HANDLE_FILE,
    HANDLE_DIRECTORY
} handle_type_t;

// An open file can sit behind several descriptors after dup
typedef struct {
    handle_type_t type;
    fs_file_handle_t* file;
    char path[FS_MAX_PATH_LENGTH];
    uint32_t flags;
    uint32_t refs;
    uint32_t directory_index;
} program_file_t;

typedef struct {
    uint64_t start;
    uint64_t length;
} program_region_t;

typedef struct {
    address_space_t as;
    program_format_t format;
    char path[FS_MAX_PATH_LENGTH];
    int argc;
    char argv[PROGRAM_MAX_ARGS][PROGRAM_ARG_LENGTH];
    uint64_t image_base;
    uint64_t image_end;
    uint64_t entry;
    uint64_t brk_start;
    uint64_t brk_end;
    uint64_t stack_low;
    program_region_t regions[PROGRAM_MAX_REGIONS];
    uint32_t region_count;
    program_file_t files[PROGRAM_MAX_HANDLES];
    int8_t fds[PROGRAM_MAX_HANDLES];
    char saved_cwd[FS_MAX_PATH_LENGTH];
    uint32_t pid;
    bool running;
} program_t;

extern program_t program;

program_format_t program_detect(const char* path);
const char* program_format_name(program_format_t format);
// Runs a native program to completion, returns false with error filled when it could not start
bool program_run(const char* path, int argc, char* argv[], int64_t* exit_code, char* error);
void program_initialize(void);

void program_exit(int64_t code) __attribute__((noreturn));
// True when the program takes Ctrl+C itself instead of being stopped, PE programs run on the same calls
bool program_signal_interrupt(void);
void program_kill(const char* reason, int64_t code) __attribute__((noreturn));

bool user_check(uint64_t address, uint64_t length, bool write);
bool user_copy_in(void* destination, uint64_t source, uint64_t length);
bool user_copy_out(uint64_t destination, const void* source, uint64_t length);
int64_t user_string(char* destination, uint64_t source, uint32_t size);

#define PROGRAM_MAP_COMMIT 1
#define PROGRAM_MAP_WRITE 2

// Without PROGRAM_MAP_COMMIT the range is only reserved, pages arrive with program_commit
uint64_t program_map(uint64_t address, uint64_t length, uint32_t flags, bool fixed);
bool program_commit(uint64_t address, uint64_t length, bool writable);
bool program_range_free(uint64_t address, uint64_t length);
void program_random(uint8_t* out, uint64_t length);
bool program_unmap(uint64_t address, uint64_t length);
bool program_reserve(uint64_t address, uint64_t length);
const program_region_t* program_region_at(uint64_t address);

int program_fd_open(handle_type_t type, uint32_t flags);
program_file_t* program_fd_get(int64_t fd);
int program_fd_dup(int64_t fd, int64_t minimum);
bool program_fd_dup_to(int64_t fd, int64_t target);
bool program_fd_close(int64_t fd);

void console_write(const char* text, uint64_t length);
int64_t console_read(char* buffer, uint64_t length);
void console_poll_keyboard(void);
bool console_input_ready(void);
void console_reset(void);
void console_set_mode(bool canonical, bool echo, bool signals);
bool console_canonical(void);
bool console_echo(void);
uint32_t console_pending(void);

// Each loader maps the image and fills the frame the program starts from
bool elf_load(const uint8_t* data, uint32_t size, interrupt_frame_t* frame, char* error);
bool bin_load(const uint8_t* data, uint32_t size, interrupt_frame_t* frame, char* error);
bool pe_load(const uint8_t* data, uint32_t size, interrupt_frame_t* frame, char* error);
uint64_t linux_build_stack(uint64_t phdr, uint32_t phnum, uint32_t phent);

void linux_syscall(interrupt_frame_t* frame);
void linux_reset(void);
bool linux_queue_signal_interrupt(void);
void linux_after_trap(interrupt_frame_t* frame);
bool linux_deliver_fault(interrupt_frame_t* frame, int signal);

#endif
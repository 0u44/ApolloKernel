#include "program.h"
#include "memory.h"
#include "terminal.h"
#include "string_utils.h"
#include "acc_bytecode.h"
#include "crypto.h"
#include "time_keeper.h"

#define EXIT_SIGNAL_BASE 128
#define SIGINT 2
#define SIGILL 4
#define SIGTRAP 5
#define SIGBUS 7
#define SIGFPE 8
#define SIGSEGV 11
#define EXCEPTION_STACK_SEGMENT 12
#define ELF_MAGIC 0x464C457Fu
#define MZ_MAGIC 0x5A4D
#define ACC_MAGIC_LENGTH 3
#define FIRST_PROGRAM_PID 100
#define RANDOM_KEY_SIZE 32
#define O_RDWR_FLAG 2

program_t program;
static uint32_t run_count;
static uint8_t random_key[RANDOM_KEY_SIZE];
static uint64_t random_counter;

typedef struct {
    uint64_t vector;
    int signal;
} fault_kind_t;

static const fault_kind_t fault_kinds[] = {
    {EXCEPTION_DIVIDE, SIGFPE},
    {EXCEPTION_DEBUG, SIGTRAP},
    {EXCEPTION_BREAKPOINT, SIGTRAP},
    {EXCEPTION_INVALID_OPCODE, SIGILL},
    {EXCEPTION_STACK_SEGMENT, SIGBUS},
    {EXCEPTION_GENERAL_PROTECTION, SIGSEGV},
    {EXCEPTION_PAGE_FAULT, SIGSEGV},
    {EXCEPTION_X87, SIGFPE},
    {EXCEPTION_ALIGNMENT, SIGBUS},
    {EXCEPTION_SIMD, SIGFPE},
};

static const fault_kind_t default_fault = {0, SIGSEGV};

/* format detection */

static bool ends_with_bin(const char* path) {
    uint32_t n = string_length(path);
    if (n < 4) return false;
    const char* e = path + n - 4;
    return e[0] == '.' && (e[1] | 0x20) == 'b' && (e[2] | 0x20) == 'i' && (e[3] | 0x20) == 'n';
}

static program_format_t detect_data(const uint8_t* data, uint32_t size, const char* path) {
    if (size >= 4 && *(const uint32_t*)data == ELF_MAGIC) return PROGRAM_FORMAT_ELF;
    if (size >= 2 && *(const uint16_t*)data == MZ_MAGIC) return PROGRAM_FORMAT_PE;
    if (size >= ACC_MAGIC_LENGTH && data[0] == ACC_MAGIC_0 && data[1] == ACC_MAGIC_1 && data[2] == ACC_MAGIC_2) {
        return PROGRAM_FORMAT_ACC;
    }
    if (size > 0 && ends_with_bin(path)) return PROGRAM_FORMAT_BIN;
    return PROGRAM_FORMAT_UNKNOWN;
}

program_format_t program_detect(const char* path) {
    fs_file_info_t info;
    if (!filesystem_get_file_info(path, &info) || info.type != FS_TYPE_FILE) return PROGRAM_FORMAT_UNKNOWN;
    return detect_data(info.data, info.size, path);
}

const char* program_format_name(program_format_t format) {
    switch (format) {
        case PROGRAM_FORMAT_ACC: return "acc";
        case PROGRAM_FORMAT_ELF: return "ELF64";
        case PROGRAM_FORMAT_PE: return "PE32+";
        case PROGRAM_FORMAT_BIN: return "flat binary";
        case PROGRAM_FORMAT_UNKNOWN: break;
    }
    return "unknown";
}

/* user memory */

// Touching the reserved stack below what is mapped grows it, the same as a fault there would
static bool grow_stack(uint64_t address) {
    uint64_t floor = USER_STACK_TOP - USER_STACK_RESERVE;
    if (address < floor || address >= program.stack_low) return false;
    uint64_t low = ALIGN_DOWN(address, PAGE_SIZE);
    if (!address_space_map(&program.as, low, program.stack_low - low, true)) return false;
    program.stack_low = low;
    return true;
}

bool user_check(uint64_t address, uint64_t length, bool write) {
    if (length == 0) return true;
    grow_stack(address);
    return address_space_range_mapped(&program.as, address, length, write);
}

bool user_copy_in(void* destination, uint64_t source, uint64_t length) {
    if (!user_check(source, length, false)) return false;
    memcpy(destination, (const void*)(uintptr_t)source, length);
    return true;
}

bool user_copy_out(uint64_t destination, const void* source, uint64_t length) {
    if (!user_check(destination, length, true)) return false;
    memcpy((void*)(uintptr_t)destination, source, length);
    return true;
}

// Returns the string length, or -1 when it is unmapped or does not fit
int64_t user_string(char* destination, uint64_t source, uint32_t size) {
    for (uint32_t i = 0; i < size; i++) {
        if ((i == 0 || ((source + i) % PAGE_SIZE) == 0) && !user_check(source + i, 1, false)) return -1;
        destination[i] = *(const char*)(uintptr_t)(source + i);
        if (destination[i] == '\0') return i;
    }
    return -1;
}

/* regions */

static void remove_region_index(uint32_t i) {
    for (uint32_t j = i; j + 1 < program.region_count; j++) program.regions[j] = program.regions[j + 1];
    program.region_count--;
}

static bool insert_region(uint64_t start, uint64_t length) {
    if (program.region_count >= PROGRAM_MAX_REGIONS) return false;
    uint32_t i = 0;
    while (i < program.region_count && program.regions[i].start < start) i++;
    for (uint32_t j = program.region_count; j > i; j--) program.regions[j] = program.regions[j - 1];
    program.regions[i] = (program_region_t){start, length};
    program.region_count++;
    return true;
}

// Cuts [start, end) out of every region it overlaps, splitting one that contains it
static void cut_regions(uint64_t start, uint64_t end) {
    for (uint32_t i = 0; i < program.region_count;) {
        program_region_t* r = &program.regions[i];
        uint64_t r_end = r->start + r->length;
        if (r_end <= start || r->start >= end) { i++; continue; }
        if (r->start >= start && r_end <= end) { remove_region_index(i); continue; }
        if (r->start < start && r_end > end) {
            r->length = start - r->start;
            insert_region(end, r_end - end);
            return;
        }
        if (r->start < start) r->length = start - r->start;
        else { r->length = r_end - end; r->start = end; }
        i++;
    }
}

static uint64_t find_gap(uint64_t length) {
    uint64_t candidate = USER_MMAP_BASE;
    for (uint32_t i = 0; i < program.region_count; i++) {
        const program_region_t* r = &program.regions[i];
        if (r->start + r->length <= candidate) continue;
        if (r->start >= candidate + length) break;
        candidate = r->start + r->length;
    }
    return candidate + length <= USER_MMAP_END ? candidate : 0;
}

bool program_range_free(uint64_t start, uint64_t length) {
    for (uint32_t i = 0; i < program.region_count; i++) {
        const program_region_t* r = &program.regions[i];
        if (r->start < start + length && start < r->start + r->length) return false;
    }
    return true;
}

bool program_reserve(uint64_t address, uint64_t length) {
    cut_regions(address, address + length);
    return insert_region(address, length);
}

uint64_t program_map(uint64_t address, uint64_t length, uint32_t flags, bool fixed) {
    length = ALIGN_UP(length, PAGE_SIZE);
    if (length == 0) return 0;
    if (fixed) {
        if (address % PAGE_SIZE || !address_space_is_user(address, length)) return 0;
        program_unmap(address, length);
    } else if (!address || address % PAGE_SIZE || !address_space_is_user(address, length) || !program_range_free(address, length)) {
        address = find_gap(length);
        if (!address) return 0;
    }
    bool commit = flags & PROGRAM_MAP_COMMIT;
    if ((commit && !address_space_map(&program.as, address, length, flags & PROGRAM_MAP_WRITE)) ||
        !program_reserve(address, length)) {
        address_space_unmap(&program.as, address, length);
        return 0;
    }
    return address;
}

// Maps the pages of a reserved range that have no frame yet
bool program_commit(uint64_t address, uint64_t length, bool writable) {
    uint64_t end = ALIGN_UP(address + length, PAGE_SIZE);
    for (uint64_t a = ALIGN_DOWN(address, PAGE_SIZE); a < end; a += PAGE_SIZE) {
        if (!program_region_at(a)) return false;
    }
    if (!address_space_map(&program.as, address, length, writable)) return false;
    address_space_protect(&program.as, address, length, writable);
    return true;
}

/* random bytes */

// SHA-256 over a key and a counter, the key is replaced after each request
void program_random(uint8_t* out, uint64_t length) {
    uint8_t block[CRYPTO_SHA256_DIGEST_SIZE];
    uint8_t input[RANDOM_KEY_SIZE + sizeof(uint64_t)];
    while (length > 0) {
        memcpy(input, random_key, RANDOM_KEY_SIZE);
        random_counter++;
        memcpy(input + RANDOM_KEY_SIZE, &random_counter, sizeof(random_counter));
        crypto_sha256(input, sizeof(input), block);
        uint64_t n = length < sizeof(block) ? length : sizeof(block);
        memcpy(out, block, n);
        out += n;
        length -= n;
    }
    random_counter++;
    memcpy(input + RANDOM_KEY_SIZE, &random_counter, sizeof(random_counter));
    crypto_sha256(input, sizeof(input), random_key);
}

static void seed_random(void) {
    uint8_t seed[RANDOM_KEY_SIZE * 2];
    memset(seed, 0, sizeof(seed));
    crypto_rng_get_bytes_nonblock(seed, RANDOM_KEY_SIZE);
    uint64_t now = time_keeper_get_uptime_ns();
    uint64_t tsc;
    __asm__ volatile("rdtsc; shlq $32, %%rdx; orq %%rdx, %%rax" : "=a"(tsc) : : "rdx");
    memcpy(seed + RANDOM_KEY_SIZE, &now, sizeof(now));
    memcpy(seed + RANDOM_KEY_SIZE + sizeof(now), &tsc, sizeof(tsc));
    memcpy(seed + RANDOM_KEY_SIZE + 2 * sizeof(now), random_key, RANDOM_KEY_SIZE - 2 * sizeof(now));
    crypto_sha256(seed, sizeof(seed), random_key);
}

bool program_unmap(uint64_t address, uint64_t length) {
    length = ALIGN_UP(length, PAGE_SIZE);
    if (address % PAGE_SIZE || !address_space_is_user(address, length)) return false;
    address_space_unmap(&program.as, address, length);
    cut_regions(address, address + length);
    return true;
}

const program_region_t* program_region_at(uint64_t address) {
    for (uint32_t i = 0; i < program.region_count; i++) {
        const program_region_t* r = &program.regions[i];
        if (address >= r->start && address < r->start + r->length) return r;
    }
    return NULL;
}

/* descriptors */

static int lowest_free_fd(int64_t minimum) {
    for (int64_t fd = minimum < 0 ? 0 : minimum; fd < PROGRAM_MAX_HANDLES; fd++) {
        if (program.fds[fd] < 0) return (int)fd;
    }
    return -1;
}

int program_fd_open(handle_type_t type, uint32_t flags) {
    int fd = lowest_free_fd(0);
    if (fd < 0) return -1;
    for (int i = 0; i < PROGRAM_MAX_HANDLES; i++) {
        if (program.files[i].type != HANDLE_FREE) continue;
        memset(&program.files[i], 0, sizeof(program_file_t));
        program.files[i].type = type;
        program.files[i].flags = flags;
        program.files[i].refs = 1;
        program.fds[fd] = (int8_t)i;
        return fd;
    }
    return -1;
}

program_file_t* program_fd_get(int64_t fd) {
    if (fd < 0 || fd >= PROGRAM_MAX_HANDLES || program.fds[fd] < 0) return NULL;
    return &program.files[program.fds[fd]];
}

int program_fd_dup(int64_t fd, int64_t minimum) {
    program_file_t* file = program_fd_get(fd);
    int target = lowest_free_fd(minimum);
    if (!file || target < 0) return -1;
    program.fds[target] = program.fds[fd];
    file->refs++;
    return target;
}

bool program_fd_dup_to(int64_t fd, int64_t target) {
    program_file_t* file = program_fd_get(fd);
    if (!file || target < 0 || target >= PROGRAM_MAX_HANDLES) return false;
    if (target == fd) return true;
    program_fd_close(target);
    program.fds[target] = program.fds[fd];
    file->refs++;
    return true;
}

bool program_fd_close(int64_t fd) {
    program_file_t* file = program_fd_get(fd);
    if (!file) return false;
    program.fds[fd] = -1;
    if (--file->refs > 0) return true;
    if (file->file) filesystem_close_file(file->file);
    file->file = NULL;
    file->type = HANDLE_FREE;
    return true;
}

/* lifecycle */

static void release_program(void) {
    cpu_timer_enable(false);
    address_space_activate(NULL);
    for (int i = 0; i < PROGRAM_MAX_HANDLES; i++) program_fd_close(i);
    address_space_destroy(&program.as);
    if (program.saved_cwd[0]) filesystem_change_directory(program.saved_cwd);
    cpu_set_fs_base(0);
    cpu_set_gs_base(0);
    program.running = false;
}

void program_exit(int64_t code) {
    release_program();
    cpu_leave_user((uint64_t)code);
}

bool program_signal_interrupt(void) {
    return linux_queue_signal_interrupt();
}

void program_kill(const char* reason, int64_t code) {
    terminal_set_color(12, 0);
    terminal_write_string("\n");
    terminal_write_string(reason);
    terminal_write_string("\n");
    terminal_set_color(7, 0);
    program_exit(code);
}

static const fault_kind_t* fault_kind(uint64_t vector) {
    for (uint32_t i = 0; i < ARRAY_SIZE(fault_kinds); i++) {
        if (fault_kinds[i].vector == vector) return &fault_kinds[i];
    }
    return &default_fault;
}

static void report_fault(const interrupt_frame_t* f) {
    terminal_set_color(12, 0);
    terminal_write_string("\nProgram fault: ");
    terminal_write_string(cpu_exception_name(f->vector));
    if (f->vector == EXCEPTION_PAGE_FAULT) {
        terminal_write_string(" at address ");
        terminal_write_hex(cpu_read_cr2());
    }
    terminal_write_string(", rip ");
    terminal_write_hex(f->rip);
    terminal_write_string("\n");
    terminal_set_color(7, 0);
}

static void handle_fault(interrupt_frame_t* frame) {
    if (frame->vector == EXCEPTION_PAGE_FAULT && grow_stack(cpu_read_cr2())) return;
    const fault_kind_t* kind = fault_kind(frame->vector);
    if (linux_deliver_fault(frame, kind->signal)) return;
    report_fault(frame);
    program_exit(EXIT_SIGNAL_BASE + kind->signal);
}

static void handle_timer(interrupt_frame_t* frame) {
    console_poll_keyboard();
    linux_after_trap(frame);
}

static void handle_syscall(interrupt_frame_t* frame) {
    linux_syscall(frame);
}

void program_initialize(void) {
    for (uint32_t v = 0; v < EXCEPTION_COUNT; v++) cpu_set_handler(v, handle_fault);
    cpu_set_handler(IRQ_TIMER_VECTOR, handle_timer);
    cpu_set_handler(SYSCALL_VECTOR, handle_syscall);
}

static bool prepare(const char* path, int argc, char* argv[], program_format_t format, char* error) {
    memset(&program, 0, sizeof(program));
    program.format = format;
    if (!filesystem_resolve_path(path, program.path, sizeof(program.path))) string_copy_n(program.path, path, sizeof(program.path));
    program.argc = argc < PROGRAM_MAX_ARGS ? argc : PROGRAM_MAX_ARGS;
    for (int i = 0; i < program.argc; i++) string_copy_n(program.argv[i], argv[i], PROGRAM_ARG_LENGTH);
    for (int i = 0; i < PROGRAM_MAX_HANDLES; i++) program.fds[i] = -1;
    program.pid = ++run_count + FIRST_PROGRAM_PID;
    seed_random();
    // A chdir inside the program must not move the shell
    filesystem_get_current_directory(program.saved_cwd, sizeof(program.saved_cwd));
    program_fd_open(HANDLE_CONSOLE_IN, O_RDWR_FLAG);
    program_fd_open(HANDLE_CONSOLE_OUT, O_RDWR_FLAG);
    program_fd_open(HANDLE_CONSOLE_OUT, O_RDWR_FLAG);
    if (!address_space_create(&program.as)) {
        string_copy(error, "not enough memory for the program's page tables");
        return false;
    }
    linux_reset();
    program.stack_low = USER_STACK_TOP - USER_STACK_COMMIT;
    if (!address_space_map(&program.as, program.stack_low, USER_STACK_COMMIT, true) ||
        !program_reserve(USER_STACK_TOP - USER_STACK_RESERVE, USER_STACK_RESERVE)) {
        string_copy(error, "not enough memory for the program's stack");
        return false;
    }
    return true;
}

static bool load(program_format_t format, const fs_file_info_t* info, interrupt_frame_t* frame, char* error) {
    switch (format) {
        case PROGRAM_FORMAT_ELF: return elf_load(info->data, info->size, frame, error);
        case PROGRAM_FORMAT_PE: return pe_load(info->data, info->size, frame, error);
        case PROGRAM_FORMAT_BIN: return bin_load(info->data, info->size, frame, error);
        default: break;
    }
    string_copy(error, "not a native program: no ELF or PE header, and the name does not end in .bin");
    return false;
}

bool program_run(const char* path, int argc, char* argv[], int64_t* exit_code, char* error) {
    fs_file_info_t info;
    if (!filesystem_get_file_info(path, &info) || info.type != FS_TYPE_FILE) {
        string_copy(error, "file not found");
        return false;
    }
    program_format_t format = detect_data(info.data, info.size, path);
    interrupt_frame_t* frame = cpu_user_frame();
    memset(frame, 0, sizeof(*frame));
    frame->cs = USER_CODE_SELECTOR;
    frame->ss = USER_DATA_SELECTOR;
    frame->rflags = RFLAGS_IF | RFLAGS_RESERVED;
    bool ok = prepare(path, argc, argv, format, error);
    // Loaders write the image through its user addresses, so the program's tables must be live
    if (ok) address_space_activate(&program.as);
    if (ok) ok = load(format, &info, frame, error);
    if (!ok) {
        release_program();
        return false;
    }
    program.running = true;
    console_reset();
    cpu_timer_enable(true);
    *exit_code = (int64_t)cpu_enter_user(frame);
    return true;
}

/* flat binaries */

// Loaded at the bottom of the program window, entered at the first byte with a Linux style stack
bool bin_load(const uint8_t* data, uint32_t size, interrupt_frame_t* frame, char* error) {
    uint64_t base = USER_WINDOW_START;
    if (base + size > memory_user_window_end()) {
        string_copy(error, "flat binary is larger than the program window");
        return false;
    }
    if (!address_space_map(&program.as, base, size, true) || !program_reserve(base, ALIGN_UP(size, PAGE_SIZE))) {
        string_copy(error, "not enough memory for the image");
        return false;
    }
    memcpy((void*)(uintptr_t)base, data, size);
    program.image_base = base;
    program.image_end = ALIGN_UP(base + size, PAGE_SIZE);
    program.brk_start = program.brk_end = program.image_end;
    program.entry = base;
    frame->rip = base;
    frame->rsp = linux_build_stack(0, 0, 0);
    if (!frame->rsp) {
        string_copy(error, "the arguments do not fit on the stack");
        return false;
    }
    return true;
}
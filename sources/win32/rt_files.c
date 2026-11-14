#include "runtime.h"

#define MAX_FDS 32
#define HANDLE_STRIDE 4
#define STD_INPUT_HANDLE ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE ((DWORD)-12)
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_ALL 0x10000000u
#define FILE_READ_DATA 0x0001
#define FILE_WRITE_DATA 0x0002
#define FILE_APPEND_DATA 0x0004
#define CREATE_NEW 1
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define OPEN_ALWAYS 4
#define TRUNCATE_EXISTING 5
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000u
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000u
#define FILE_TYPE_UNKNOWN 0
#define FILE_TYPE_DISK 1
#define FILE_TYPE_CHAR 2
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define FILE_ATTRIBUTE_ARCHIVE 0x20
#define INVALID_FILE_ATTRIBUTES 0xFFFFFFFFu
#define MOVEFILE_REPLACE_EXISTING 0x1
#define ENABLE_PROCESSED_INPUT 0x1
#define ENABLE_LINE_INPUT 0x2
#define ENABLE_ECHO_INPUT 0x4
#define ENABLE_PROCESSED_OUTPUT 0x1
#define ENABLE_WRAP_AT_EOL_OUTPUT 0x2
#define CODE_PAGE_UTF8 65001
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0x40
#define O_EXCL 0x80
#define O_TRUNC 0x200
#define O_APPEND 0x400
#define O_DIRECTORY 0x10000
#define AT_REMOVEDIR 0x200
#define SEEK_CUR 1
#define TCGETS 0x5401
#define TCSETS 0x5402
#define TERMIOS_ICANON 0x2
#define TERMIOS_ECHO 0x8
#define TERMIOS_ISIG 0x1
#define TERMIOS_SIZE 36
#define TERMIOS_LFLAG_OFFSET 12
#define PATH_LIMIT 256
#define CONSOLE_BUFFER 512
#define DIRENT_BUFFER 4096
#define DIRENT_NAME 19
#define FIND_NAME_LENGTH 260
#define FIND_DATA_SIZE 592
#define FIND_ATTRIBUTES 0
#define FIND_CREATION 4
#define FIND_ACCESS 12
#define FIND_WRITE 20
#define FIND_SIZE_HIGH 28
#define FIND_SIZE_LOW 32
#define FIND_NAME 44
#define FILETIME_UNIX_EPOCH 116444736000000000ULL
#define TICKS_PER_SECOND 10000000ULL
#define OVERLAPPED_OFFSET 16
#define SURROGATE_HIGH_FIRST 0xD800
#define SURROGATE_LOW_FIRST 0xDC00
#define LINUX_PREAD64 17
#define LINUX_PWRITE64 18

typedef struct {
    bool delete_on_close;
    char path[PATH_LIMIT];
} fd_info_t;

typedef struct {
    char directory[PATH_LIMIT];
    char** names;
    uint32_t count;
    uint32_t next;
} find_state_t;

static fd_info_t fd_info[MAX_FDS];
static HANDLE std_handles[3];
static DWORD console_input_mode = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
static char console_bytes[CONSOLE_BUFFER];
static uint32_t console_bytes_length;
static uint32_t console_bytes_position;
static bool console_pending_newline;

HANDLE rt_fd_handle(int64_t fd) {
    return (HANDLE)(uint64_t)((fd + 1) * HANDLE_STRIDE);
}

int64_t rt_handle_fd(HANDLE handle) {
    uint64_t value = (uint64_t)handle;
    if (value % HANDLE_STRIDE || value < HANDLE_STRIDE || value > MAX_FDS * HANDLE_STRIDE) return -1;
    return (int64_t)(value / HANDLE_STRIDE) - 1;
}

void rt_files_initialize(void) {
    for (int i = 0; i < 3; i++) std_handles[i] = rt_fd_handle(i);
}

static bool fd_stat(int64_t fd, linux_stat_t* st) {
    return fd >= 0 && sys2(LINUX_FSTAT, fd, st) == 0;
}

static bool is_console(int64_t fd) {
    linux_stat_t st;
    return fd_stat(fd, &st) && (st.mode & S_IFMT) == S_IFCHR;
}

static int64_t checked_fd(HANDLE handle) {
    int64_t fd = rt_handle_fd(handle);
    linux_stat_t st;
    if (!fd_stat(fd, &st)) {
        rt_set_last_error(ERROR_INVALID_HANDLE);
        return -1;
    }
    return fd;
}

WINAPI HANDLE GetStdHandle(DWORD which) {
    if (which == STD_INPUT_HANDLE) return std_handles[0];
    if (which == STD_OUTPUT_HANDLE) return std_handles[1];
    if (which == STD_ERROR_HANDLE) return std_handles[2];
    rt_set_last_error(ERROR_INVALID_HANDLE);
    return INVALID_HANDLE_VALUE;
}

WINAPI BOOL SetStdHandle(DWORD which, HANDLE handle) {
    if (which == STD_INPUT_HANDLE) std_handles[0] = handle;
    else if (which == STD_OUTPUT_HANDLE) std_handles[1] = handle;
    else if (which == STD_ERROR_HANDLE) std_handles[2] = handle;
    else {
        rt_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    return TRUE;
}

WINAPI BOOL CloseHandle(HANDLE handle) {
    if (handle == CURRENT_PROCESS_HANDLE || handle == CURRENT_THREAD_HANDLE) return TRUE;
    int64_t fd = checked_fd(handle);
    if (fd < 0) return FALSE;
    sys1(LINUX_CLOSE, fd);
    if (fd < MAX_FDS && fd_info[fd].delete_on_close) sys3(LINUX_UNLINKAT, LINUX_AT_FDCWD, fd_info[fd].path, 0);
    if (fd < MAX_FDS) fd_info[fd].delete_on_close = false;
    return TRUE;
}

static bool path_exists(const char* path, linux_stat_t* st) {
    return sys4(LINUX_NEWFSTATAT, LINUX_AT_FDCWD, path, st, 0) == 0;
}

static DWORD missing_error(const char* path) {
    char parent[PATH_LIMIT];
    uint32_t n = (uint32_t)rt_strlen(path);
    while (n > 0 && path[n - 1] != '/') n--;
    if (n <= 1) return ERROR_FILE_NOT_FOUND;
    memcpy(parent, path, n - 1);
    parent[n - 1] = '\0';
    linux_stat_t st;
    return path_exists(parent, &st) ? ERROR_FILE_NOT_FOUND : ERROR_PATH_NOT_FOUND;
}

static int access_flags(DWORD access) {
    bool read = access & (GENERIC_READ | GENERIC_ALL | FILE_READ_DATA);
    bool write = access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA);
    if (read && write) return O_RDWR;
    if (write) return (access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA)) ? O_WRONLY : (O_WRONLY | O_APPEND);
    return O_RDONLY;
}

static HANDLE open_console(const WCHAR* name) {
    int64_t source = rt_wide_names_equal(name, "CONIN$") ? 0 : 1;
    int64_t fd = sys1(LINUX_DUP, source);
    if (fd < 0) {
        rt_set_error_from(fd);
        return INVALID_HANDLE_VALUE;
    }
    return rt_fd_handle(fd);
}

static int disposition_flags(DWORD disposition, bool exists, DWORD* error) {
    *error = ERROR_SUCCESS;
    switch (disposition) {
        case CREATE_NEW: if (exists) *error = ERROR_FILE_EXISTS; return O_CREAT | O_EXCL;
        case CREATE_ALWAYS: return O_CREAT | O_TRUNC;
        case OPEN_EXISTING: return 0;
        case OPEN_ALWAYS: return O_CREAT;
        case TRUNCATE_EXISTING: if (!exists) *error = ERROR_FILE_NOT_FOUND; return O_TRUNC;
        default: *error = ERROR_INVALID_PARAMETER; return 0;
    }
}

WINAPI HANDLE CreateFileW(const WCHAR* name, DWORD access, DWORD share, void* security, DWORD disposition, DWORD flags, HANDLE templ) {
    (void)share; (void)security; (void)templ;
    if (rt_wide_names_equal(name, "CONIN$") || rt_wide_names_equal(name, "CONOUT$")) return open_console(name);
    char path[PATH_LIMIT];
    if (!rt_path_from_wide(name, path, sizeof(path))) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    linux_stat_t st;
    bool exists = path_exists(path, &st);
    bool directory = exists && (st.mode & S_IFMT) == S_IFDIR;
    if (directory && !(flags & FILE_FLAG_BACKUP_SEMANTICS)) {
        rt_set_last_error(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    DWORD error = ERROR_SUCCESS;
    int open_flags = directory ? (O_RDONLY | O_DIRECTORY) : access_flags(access) | disposition_flags(disposition, exists, &error);
    if (!directory && error != ERROR_SUCCESS) {
        rt_set_last_error(error);
        return INVALID_HANDLE_VALUE;
    }
    if (!exists && disposition == OPEN_EXISTING) {
        rt_set_last_error(missing_error(path));
        return INVALID_HANDLE_VALUE;
    }
    int64_t fd = sys4(LINUX_OPENAT, LINUX_AT_FDCWD, path, open_flags, 0644);
    if (fd < 0) {
        rt_set_last_error(fd == -LINUX_ENOENT ? missing_error(path) : rt_error_from_errno(fd));
        return INVALID_HANDLE_VALUE;
    }
    if (fd < MAX_FDS) {
        fd_info[fd].delete_on_close = (flags & FILE_FLAG_DELETE_ON_CLOSE) != 0;
        memcpy(fd_info[fd].path, path, sizeof(path));
    }
    bool reports_existing = disposition == CREATE_ALWAYS || disposition == OPEN_ALWAYS;
    rt_set_last_error(exists && reports_existing ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
    return rt_fd_handle(fd);
}

static bool fill_console_bytes(int64_t fd) {
    int64_t n = sys3(LINUX_READ, fd, console_bytes, sizeof(console_bytes));
    if (n <= 0) return false;
    console_bytes_length = (uint32_t)n;
    console_bytes_position = 0;
    return true;
}

static uint32_t read_console_bytes(int64_t fd, char* out, uint32_t size) {
    uint32_t n = 0;
    if (console_bytes_position >= console_bytes_length && !console_pending_newline && !fill_console_bytes(fd)) return 0;
    bool line_mode = console_input_mode & ENABLE_LINE_INPUT;
    while (n < size) {
        if (console_pending_newline) {
            out[n++] = '\n';
            console_pending_newline = false;
            continue;
        }
        if (console_bytes_position >= console_bytes_length) break;
        char c = console_bytes[console_bytes_position++];
        if (c == '\n' && line_mode) {
            out[n++] = '\r';
            console_pending_newline = true;
            continue;
        }
        out[n++] = c;
    }
    return n;
}

WINAPI BOOL ReadFile(HANDLE handle, void* buffer, DWORD size, DWORD* done, void* overlapped) {
    int64_t fd = checked_fd(handle);
    if (done) *done = 0;
    if (fd < 0) return FALSE;
    int64_t n;
    if (is_console(fd)) n = read_console_bytes(fd, buffer, size);
    else if (overlapped) n = sys4(LINUX_PREAD64, fd, buffer, size, *(uint64_t*)((uint8_t*)overlapped + OVERLAPPED_OFFSET));
    else n = sys3(LINUX_READ, fd, buffer, size);
    if (n < 0) {
        rt_set_error_from(n);
        return FALSE;
    }
    if (done) *done = (DWORD)n;
    return TRUE;
}

WINAPI BOOL WriteFile(HANDLE handle, const void* buffer, DWORD size, DWORD* done, void* overlapped) {
    int64_t fd = checked_fd(handle);
    if (done) *done = 0;
    if (fd < 0) return FALSE;
    DWORD total = 0;
    uint64_t offset = overlapped ? *(uint64_t*)((uint8_t*)overlapped + OVERLAPPED_OFFSET) : 0;
    while (total < size) {
        const uint8_t* from = (const uint8_t*)buffer + total;
        int64_t n = overlapped ? sys4(LINUX_PWRITE64, fd, from, size - total, offset + total) : sys3(LINUX_WRITE, fd, from, size - total);
        if (n <= 0) {
            rt_set_error_from(n == 0 ? -LINUX_ENOENT : n);
            if (done) *done = total;
            return FALSE;
        }
        total += (DWORD)n;
    }
    if (done) *done = total;
    return TRUE;
}

WINAPI BOOL SetFilePointerEx(HANDLE handle, int64_t distance, int64_t* position, DWORD method) {
    int64_t fd = checked_fd(handle);
    if (fd < 0) return FALSE;
    int64_t r = sys3(LINUX_LSEEK, fd, distance, method);
    if (r < 0) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (position) *position = r;
    return TRUE;
}

WINAPI BOOL GetFileSizeEx(HANDLE handle, int64_t* size) {
    linux_stat_t st;
    int64_t fd = checked_fd(handle);
    if (fd < 0 || !fd_stat(fd, &st)) return FALSE;
    *size = st.size;
    return TRUE;
}

WINAPI DWORD GetFileType(HANDLE handle) {
    linux_stat_t st;
    int64_t fd = rt_handle_fd(handle);
    if (!fd_stat(fd, &st)) {
        rt_set_last_error(ERROR_INVALID_HANDLE);
        return FILE_TYPE_UNKNOWN;
    }
    rt_set_last_error(ERROR_SUCCESS);
    return (st.mode & S_IFMT) == S_IFCHR ? FILE_TYPE_CHAR : FILE_TYPE_DISK;
}

WINAPI BOOL FlushFileBuffers(HANDLE handle) {
    int64_t fd = checked_fd(handle);
    if (fd < 0) return FALSE;
    if (is_console(fd)) {
        rt_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    return sys1(LINUX_FSYNC, fd) == 0;
}

WINAPI BOOL SetEndOfFile(HANDLE handle) {
    int64_t fd = checked_fd(handle);
    if (fd < 0) return FALSE;
    int64_t position = sys3(LINUX_LSEEK, fd, 0, SEEK_CUR);
    int64_t r = position < 0 ? position : sys2(LINUX_FTRUNCATE, fd, position);
    if (r < 0) {
        rt_set_error_from(r);
        return FALSE;
    }
    return TRUE;
}

static bool wide_path(const WCHAR* name, char* path) {
    if (rt_path_from_wide(name, path, PATH_LIMIT)) return true;
    rt_set_last_error(ERROR_INVALID_PARAMETER);
    return false;
}

static BOOL result_of(int64_t r) {
    if (r >= 0) return TRUE;
    rt_set_error_from(r);
    return FALSE;
}

WINAPI BOOL DeleteFileW(const WCHAR* name) {
    char path[PATH_LIMIT];
    return wide_path(name, path) && result_of(sys3(LINUX_UNLINKAT, LINUX_AT_FDCWD, path, 0));
}

WINAPI BOOL CreateDirectoryW(const WCHAR* name, void* security) {
    (void)security;
    char path[PATH_LIMIT];
    if (!wide_path(name, path)) return FALSE;
    int64_t r = sys3(LINUX_MKDIRAT, LINUX_AT_FDCWD, path, 0755);
    if (r == -LINUX_EEXIST) {
        rt_set_last_error(ERROR_ALREADY_EXISTS);
        return FALSE;
    }
    return result_of(r);
}

WINAPI BOOL RemoveDirectoryW(const WCHAR* name) {
    char path[PATH_LIMIT];
    return wide_path(name, path) && result_of(sys3(LINUX_UNLINKAT, LINUX_AT_FDCWD, path, AT_REMOVEDIR));
}

WINAPI BOOL MoveFileExW(const WCHAR* from, const WCHAR* to, DWORD flags) {
    char source[PATH_LIMIT], target[PATH_LIMIT];
    linux_stat_t st;
    if (!wide_path(from, source) || !wide_path(to, target)) return FALSE;
    if (!(flags & MOVEFILE_REPLACE_EXISTING) && path_exists(target, &st)) {
        rt_set_last_error(ERROR_ALREADY_EXISTS);
        return FALSE;
    }
    return result_of(sys4(LINUX_RENAMEAT, LINUX_AT_FDCWD, source, LINUX_AT_FDCWD, target));
}

static DWORD attributes_of(const linux_stat_t* st) {
    return (st->mode & S_IFMT) == S_IFDIR ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
}

WINAPI DWORD GetFileAttributesW(const WCHAR* name) {
    char path[PATH_LIMIT];
    linux_stat_t st;
    if (!wide_path(name, path)) return INVALID_FILE_ATTRIBUTES;
    if (!path_exists(path, &st)) {
        rt_set_last_error(missing_error(path));
        return INVALID_FILE_ATTRIBUTES;
    }
    return attributes_of(&st);
}

WINAPI DWORD GetCurrentDirectoryW(DWORD size, WCHAR* buffer) {
    char cwd[PATH_LIMIT];
    bool invalid = false;
    if (sys2(LINUX_GETCWD, cwd, sizeof(cwd)) < 0) {
        rt_set_last_error(ERROR_PATH_NOT_FOUND);
        return 0;
    }
    uint32_t needed = rt_utf8_to_utf16(cwd, (uint32_t)rt_strlen(cwd), NULL, 0, &invalid);
    if (needed + 1 > size) return needed + 1;
    rt_utf8_to_utf16(cwd, (uint32_t)rt_strlen(cwd), buffer, needed, &invalid);
    buffer[needed] = 0;
    return needed;
}

WINAPI BOOL SetCurrentDirectoryW(const WCHAR* name) {
    char path[PATH_LIMIT];
    return wide_path(name, path) && result_of(sys1(LINUX_CHDIR, path));
}

WINAPI BOOL GetConsoleMode(HANDLE handle, DWORD* mode) {
    int64_t fd = rt_handle_fd(handle);
    if (!is_console(fd)) {
        rt_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    *mode = fd == 0 ? console_input_mode : (ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);
    return TRUE;
}

WINAPI BOOL SetConsoleMode(HANDLE handle, DWORD mode) {
    int64_t fd = rt_handle_fd(handle);
    if (!is_console(fd)) {
        rt_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (fd != 0) return TRUE;
    uint8_t termios[TERMIOS_SIZE];
    sys3(LINUX_IOCTL, fd, TCGETS, termios);
    uint32_t* lflag = (uint32_t*)(termios + TERMIOS_LFLAG_OFFSET);
    *lflag &= ~(uint32_t)(TERMIOS_ICANON | TERMIOS_ECHO | TERMIOS_ISIG);
    if (mode & ENABLE_LINE_INPUT) *lflag |= TERMIOS_ICANON;
    if (mode & ENABLE_ECHO_INPUT) *lflag |= TERMIOS_ECHO;
    if (mode & ENABLE_PROCESSED_INPUT) *lflag |= TERMIOS_ISIG;
    sys3(LINUX_IOCTL, fd, TCSETS, termios);
    console_input_mode = mode;
    return TRUE;
}

WINAPI UINT GetConsoleOutputCP(void) {
    return CODE_PAGE_UTF8;
}

WINAPI UINT GetConsoleCP(void) {
    return CODE_PAGE_UTF8;
}

WINAPI BOOL WriteConsoleW(HANDLE handle, const WCHAR* text, DWORD count, DWORD* written, void* reserved) {
    (void)reserved;
    char buffer[CONSOLE_BUFFER];
    DWORD done = 0;
    bool invalid = false;
    while (done < count) {
        DWORD chunk = count - done < CONSOLE_BUFFER / 4 ? count - done : CONSOLE_BUFFER / 4;
        if (done + chunk < count && text[done + chunk - 1] >= SURROGATE_HIGH_FIRST && text[done + chunk - 1] < SURROGATE_LOW_FIRST) chunk--;
        uint32_t n = rt_utf16_to_utf8(text + done, chunk, buffer, sizeof(buffer), &invalid);
        DWORD wrote;
        if (!WriteFile(handle, buffer, n, &wrote, NULL)) return FALSE;
        done += chunk;
    }
    if (written) *written = count;
    return TRUE;
}

WINAPI BOOL ReadConsoleW(HANDLE handle, WCHAR* buffer, DWORD count, DWORD* read, void* control) {
    (void)control;
    int64_t fd = checked_fd(handle);
    if (read) *read = 0;
    if (fd < 0) return FALSE;
    char bytes[CONSOLE_BUFFER];
    uint32_t limit = count < sizeof(bytes) ? count : sizeof(bytes);
    uint32_t n = read_console_bytes(fd, bytes, limit);
    bool invalid = false;
    uint32_t w = rt_utf8_to_utf16(bytes, n, buffer, count, &invalid);
    if (read) *read = w < count ? w : count;
    return TRUE;
}

static bool wildcard_match(const char* pattern, const char* name) {
    if (*pattern == '\0') return *name == '\0';
    if (*pattern == '*') {
        for (const char* n = name;; n++) {
            if (wildcard_match(pattern + 1, n)) return true;
            if (*n == '\0') return false;
        }
    }
    if (*name == '\0') return false;
    char p = (*pattern >= 'A' && *pattern <= 'Z') ? (char)(*pattern + 32) : *pattern;
    char c = (*name >= 'A' && *name <= 'Z') ? (char)(*name + 32) : *name;
    return (p == '?' || p == c) && wildcard_match(pattern + 1, name + 1);
}

static bool name_matches(const char* pattern, const char* name) {
    if (rt_strcmp(pattern, "*.*") == 0) return true;
    return wildcard_match(pattern, name);
}

static bool add_name(find_state_t* find, const char* name) {
    char** grown = rt_alloc((find->count + 1) * sizeof(char*));
    char* copy = rt_alloc(rt_strlen(name) + 1);
    if (!grown || !copy) return false;
    if (find->names) memcpy(grown, find->names, find->count * sizeof(char*));
    rt_free(find->names);
    memcpy(copy, name, rt_strlen(name) + 1);
    grown[find->count++] = copy;
    find->names = grown;
    return true;
}

static bool collect(find_state_t* find, const char* pattern) {
    int64_t fd = sys4(LINUX_OPENAT, LINUX_AT_FDCWD, find->directory, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return false;
    uint8_t buffer[DIRENT_BUFFER];
    int64_t n;
    while ((n = sys3(LINUX_GETDENTS64, fd, buffer, sizeof(buffer))) > 0) {
        for (int64_t at = 0; at < n; at += *(uint16_t*)(buffer + at + 16)) {
            const char* name = (const char*)buffer + at + DIRENT_NAME;
            if (name_matches(pattern, name) && !add_name(find, name)) break;
        }
    }
    sys1(LINUX_CLOSE, fd);
    return true;
}

static void put_filetime(uint8_t* at, uint64_t seconds) {
    uint64_t value = seconds * TICKS_PER_SECOND + FILETIME_UNIX_EPOCH;
    memcpy(at, &value, sizeof(value));
}

static void fill_find_data(const find_state_t* find, const char* name, uint8_t* data) {
    char path[PATH_LIMIT * 2];
    linux_stat_t st;
    memset(data, 0, FIND_DATA_SIZE);
    uint32_t d = (uint32_t)rt_strlen(find->directory), n = (uint32_t)rt_strlen(name);
    memcpy(path, find->directory, d);
    path[d] = '/';
    memcpy(path + d + 1, name, n + 1);
    if (path_exists(path, &st)) {
        *(DWORD*)(data + FIND_ATTRIBUTES) = attributes_of(&st);
        put_filetime(data + FIND_CREATION, st.ctime);
        put_filetime(data + FIND_ACCESS, st.atime);
        put_filetime(data + FIND_WRITE, st.mtime);
        *(DWORD*)(data + FIND_SIZE_HIGH) = (DWORD)((uint64_t)st.size >> 32);
        *(DWORD*)(data + FIND_SIZE_LOW) = (DWORD)st.size;
    }
    bool invalid = false;
    uint32_t w = rt_utf8_to_utf16(name, n, (WCHAR*)(data + FIND_NAME), FIND_NAME_LENGTH - 1, &invalid);
    ((WCHAR*)(data + FIND_NAME))[w < FIND_NAME_LENGTH ? w : FIND_NAME_LENGTH - 1] = 0;
}

static void free_find(find_state_t* find) {
    for (uint32_t i = 0; i < find->count; i++) rt_free(find->names[i]);
    rt_free(find->names);
    rt_free(find);
}

static void split_pattern(const char* path, char* directory, const char** pattern) {
    uint32_t n = (uint32_t)rt_strlen(path);
    uint32_t slash = n;
    while (slash > 0 && path[slash - 1] != '/') slash--;
    *pattern = path + slash;
    if (slash == 0) { directory[0] = '.'; directory[1] = '\0'; return; }
    uint32_t keep = slash > 1 ? slash - 1 : 1;
    memcpy(directory, path, keep);
    directory[keep] = '\0';
}

WINAPI HANDLE FindFirstFileExW(const WCHAR* name, int level, void* data, int search, void* filter, DWORD flags) {
    (void)level; (void)search; (void)filter; (void)flags;
    char path[PATH_LIMIT];
    const char* pattern;
    find_state_t* find = rt_alloc_zero(sizeof(find_state_t));
    if (!find) { rt_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    if (!wide_path(name, path)) { free_find(find); return INVALID_HANDLE_VALUE; }
    split_pattern(path, find->directory, &pattern);
    if (!collect(find, pattern)) {
        rt_set_last_error(ERROR_PATH_NOT_FOUND);
        free_find(find);
        return INVALID_HANDLE_VALUE;
    }
    if (find->count == 0) {
        rt_set_last_error(ERROR_FILE_NOT_FOUND);
        free_find(find);
        return INVALID_HANDLE_VALUE;
    }
    fill_find_data(find, find->names[0], data);
    find->next = 1;
    return find;
}

WINAPI BOOL FindNextFileW(HANDLE handle, void* data) {
    find_state_t* find = handle;
    if (!find || find->next >= find->count) {
        rt_set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    fill_find_data(find, find->names[find->next++], data);
    return TRUE;
}

WINAPI BOOL FindClose(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        rt_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    free_find(handle);
    return TRUE;
}
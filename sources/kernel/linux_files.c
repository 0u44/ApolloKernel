#include "linux_abi.h"
#include "string_utils.h"
#include "memory.h"

#define O_ACCMODE 3
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0x40
#define O_EXCL 0x80
#define O_TRUNC 0x200
#define O_APPEND 0x400
#define O_NONBLOCK 0x800
#define O_DIRECTORY 0x10000
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_DUPFD_CLOEXEC 1030
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define AT_EMPTY_PATH 0x1000
#define AT_REMOVEDIR 0x200
#define R_OK 4
#define W_OK 2
#define X_OK 1
#define S_IFREG 0100000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define MODE_FILE 0644
#define MODE_EXEC 0755
#define MODE_TTY 0620
#define TTY_RDEV 0x8800
#define BLOCK_SIZE 4096
#define STAT_BLOCK_UNIT 512
#define DT_REG 8
#define DT_DIR 4
#define DIRENT_HEADER 19
#define DIRENT_ALIGN 8
#define IOV_MAX 1024
#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404
#define TIOCGWINSZ 0x5413
#define FIONREAD 0x541B
#define TIOCGPGRP 0x540F
#define TERMIOS_ICRNL 0x100
#define TERMIOS_ISIG 0x1
#define TERMIOS_ICANON 0x2
#define TERMIOS_ECHO 0x8
#define TERMIOS_NCCS 19
#define CONSOLE_ROWS 25
#define CONSOLE_COLS 80
#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME 1099511628211ULL
#define DIRECTORY_SCAN_MAX FS_MAX_FILES

typedef struct {
    uint64_t dev, ino, nlink;
    uint32_t mode, uid, gid, pad;
    uint64_t rdev;
    int64_t size, blksize, blocks;
    uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    int64_t reserved[3];
} linux_stat_t;

typedef struct {
    uint32_t iflag, oflag, cflag, lflag;
    uint8_t line;
    uint8_t cc[TERMIOS_NCCS];
} PACKED linux_termios_t;

typedef struct {
    uint16_t rows, cols, xpixel, ypixel;
} linux_winsize_t;

typedef struct {
    uint64_t base;
    uint64_t length;
} linux_iovec_t;

static const linux_termios_t default_termios = {
    0x0500, 0x0005, 0x00BF, 0x8A3B, 0,
    {3, 0x1C, 0x7F, 0x15, 4, 0, 1, 0, 0x11, 0x13, 0x1A, 0, 0x12, 0x0F, 0x17, 0x16, 0, 0, 0}
};

static linux_termios_t termios;
static fs_dir_entry_t directory_entries[DIRECTORY_SCAN_MAX];

void linux_files_reset(void) {
    termios = default_termios;
}

/* paths */

static int64_t copy_path(uint64_t user_path, char* out) {
    int64_t n = user_string(out, user_path, FS_MAX_PATH_LENGTH);
    if (n < 0) return -EFAULT;
    return 0;
}

// Joins a relative path to the directory dirfd names, AT_FDCWD and absolute paths pass through
static int64_t resolve_at(int64_t dirfd, uint64_t user_path, char* out) {
    char relative[FS_MAX_PATH_LENGTH];
    if (copy_path(user_path, relative) < 0) return -EFAULT;
    if (relative[0] == '/' || dirfd == AT_FDCWD) {
        string_copy(out, relative);
        return 0;
    }
    program_file_t* dir = program_fd_get(dirfd);
    if (!dir) return -EBADF;
    if (dir->type != HANDLE_DIRECTORY) return -ENOTDIR;
    if (string_length(dir->path) + string_length(relative) + 2 > FS_MAX_PATH_LENGTH) return -ENAMETOOLONG;
    string_copy(out, dir->path);
    string_concat(out, "/");
    string_concat(out, relative);
    return 0;
}

static uint64_t path_inode(const char* path) {
    uint64_t hash = FNV_OFFSET;
    for (; *path; path++) hash = (hash ^ (uint8_t)*path) * FNV_PRIME;
    return hash;
}

/* stat */

static void fill_stat_from_info(linux_stat_t* st, const fs_file_info_t* info, const char* path) {
    memset(st, 0, sizeof(*st));
    bool directory = info->type == FS_TYPE_DIRECTORY;
    st->ino = path_inode(path);
    st->nlink = 1;
    st->mode = directory ? (S_IFDIR | MODE_EXEC) : (S_IFREG | ((info->permissions & FS_PERM_EXECUTE) ? MODE_EXEC : MODE_FILE));
    st->size = directory ? 0 : info->size;
    st->blksize = BLOCK_SIZE;
    st->blocks = (int64_t)(info->capacity_pages * (PAGE_SIZE / STAT_BLOCK_UNIT));
    st->atime = st->mtime = info->modified_time;
    st->ctime = info->created_time;
}

static void fill_stat_console(linux_stat_t* st) {
    memset(st, 0, sizeof(*st));
    st->ino = 1;
    st->nlink = 1;
    st->mode = S_IFCHR | MODE_TTY;
    st->rdev = TTY_RDEV;
    st->blksize = BLOCK_SIZE;
}

static int64_t stat_path(const char* path, uint64_t user_buffer) {
    fs_file_info_t info;
    if (!filesystem_get_file_info(path, &info)) return -ENOENT;
    linux_stat_t st;
    fill_stat_from_info(&st, &info, path);
    return user_copy_out(user_buffer, &st, sizeof(st)) ? 0 : -EFAULT;
}

static int64_t stat_fd(int64_t fd, uint64_t user_buffer) {
    program_file_t* file = program_fd_get(fd);
    if (!file) return -EBADF;
    if (file->type == HANDLE_FILE || file->type == HANDLE_DIRECTORY) return stat_path(file->path, user_buffer);
    linux_stat_t st;
    fill_stat_console(&st);
    return user_copy_out(user_buffer, &st, sizeof(st)) ? 0 : -EFAULT;
}

int64_t linux_stat(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    if (copy_path(ARG0(f), path) < 0) return -EFAULT;
    return stat_path(path, ARG1(f));
}

int64_t linux_fstat(interrupt_frame_t* f) {
    return stat_fd((int64_t)ARG0(f), ARG1(f));
}

int64_t linux_newfstatat(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    if ((ARG3(f) & AT_EMPTY_PATH)) {
        if (user_string(path, ARG1(f), sizeof(path)) == 0) return stat_fd((int64_t)ARG0(f), ARG2(f));
    }
    int64_t r = resolve_at((int64_t)ARG0(f), ARG1(f), path);
    return r < 0 ? r : stat_path(path, ARG2(f));
}

/* open and close */

static int64_t open_directory(const char* path, uint32_t flags) {
    if ((flags & O_ACCMODE) != O_RDONLY) return -EISDIR;
    int fd = program_fd_open(HANDLE_DIRECTORY, flags);
    if (fd < 0) return -EMFILE;
    string_copy(program_fd_get(fd)->path, path);
    return fd;
}

static int64_t open_path(const char* path, uint32_t flags) {
    fs_file_info_t info;
    bool exists = filesystem_get_file_info(path, &info);
    if (exists && info.type == FS_TYPE_DIRECTORY) return open_directory(path, flags);
    if (flags & O_DIRECTORY) return exists ? -ENOTDIR : -ENOENT;
    if (exists && (flags & O_CREAT) && (flags & O_EXCL)) return -EEXIST;
    if (!exists && !(flags & O_CREAT)) return -ENOENT;
    if (!exists && !filesystem_create_file(path)) return -ENOENT;
    bool writable = (flags & O_ACCMODE) != O_RDONLY;
    if (writable && (flags & O_TRUNC)) filesystem_truncate_file(path, 0);
    int fd = program_fd_open(HANDLE_FILE, flags);
    if (fd < 0) return -EMFILE;
    program_file_t* file = program_fd_get(fd);
    string_copy(file->path, path);
    file->file = filesystem_open_file(path, writable);
    if (!file->file) {
        program_fd_close(fd);
        return -ENOMEM;
    }
    return fd;
}

int64_t linux_open(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    if (copy_path(ARG0(f), path) < 0) return -EFAULT;
    return open_path(path, (uint32_t)ARG1(f));
}

int64_t linux_openat(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    int64_t r = resolve_at((int64_t)ARG0(f), ARG1(f), path);
    return r < 0 ? r : open_path(path, (uint32_t)ARG2(f));
}

int64_t linux_close(interrupt_frame_t* f) {
    return program_fd_close((int64_t)ARG0(f)) ? 0 : -EBADF;
}

/* reading and writing */

static uint32_t file_size(const program_file_t* file) {
    fs_file_info_t info;
    return filesystem_get_file_info(file->path, &info) ? info.size : 0;
}

// Enter arrives as a newline, a program that turned ICRNL off expects the carriage return a terminal sends
static int64_t read_console(uint64_t buffer, uint64_t length) {
    int64_t n = console_read((char*)(uintptr_t)buffer, length);
    if (n < 0) return -ERESTARTSYS;
    if (!(termios.iflag & TERMIOS_ICRNL)) {
        char* text = (char*)(uintptr_t)buffer;
        for (int64_t i = 0; i < n; i++) if (text[i] == '\n') text[i] = '\r';
    }
    return n;
}

static int64_t read_fd(int64_t fd, uint64_t buffer, uint64_t length) {
    program_file_t* file = program_fd_get(fd);
    if (!file) return -EBADF;
    if (file->type == HANDLE_DIRECTORY) return -EISDIR;
    if ((file->flags & O_ACCMODE) == O_WRONLY && file->type == HANDLE_FILE) return -EBADF;
    if (!user_check(buffer, length, true)) return -EFAULT;
    if (file->type == HANDLE_FILE) return filesystem_read_file(file->file, (void*)(uintptr_t)buffer, (uint32_t)length);
    return read_console(buffer, length);
}

static int64_t write_fd(int64_t fd, uint64_t buffer, uint64_t length) {
    program_file_t* file = program_fd_get(fd);
    if (!file) return -EBADF;
    if (file->type == HANDLE_DIRECTORY) return -EISDIR;
    if (!user_check(buffer, length, false)) return -EFAULT;
    if (file->type != HANDLE_FILE) {
        console_write((const char*)(uintptr_t)buffer, length);
        return (int64_t)length;
    }
    if ((file->flags & O_ACCMODE) == O_RDONLY) return -EBADF;
    if (file->flags & O_APPEND) filesystem_seek_file(file->file, file_size(file));
    if (length > FS_MAX_FILE_SIZE) length = FS_MAX_FILE_SIZE;
    uint32_t written = filesystem_write_file(file->file, (const void*)(uintptr_t)buffer, (uint32_t)length);
    return (written == 0 && length > 0) ? -EFBIG : written;
}

int64_t linux_read(interrupt_frame_t* f) {
    return read_fd((int64_t)ARG0(f), ARG1(f), ARG2(f));
}

int64_t linux_write(interrupt_frame_t* f) {
    return write_fd((int64_t)ARG0(f), ARG1(f), ARG2(f));
}

static int64_t transfer_vector(interrupt_frame_t* f, bool write) {
    uint64_t count = ARG2(f);
    if (count > IOV_MAX) return -EINVAL;
    int64_t total = 0;
    for (uint64_t i = 0; i < count; i++) {
        linux_iovec_t v;
        if (!user_copy_in(&v, ARG1(f) + i * sizeof(v), sizeof(v))) return -EFAULT;
        if (v.length == 0) continue;
        int64_t n = write ? write_fd((int64_t)ARG0(f), v.base, v.length) : read_fd((int64_t)ARG0(f), v.base, v.length);
        if (n < 0) return total > 0 ? total : n;
        total += n;
        if ((uint64_t)n < v.length) break;
    }
    return total;
}

int64_t linux_readv(interrupt_frame_t* f) {
    return transfer_vector(f, false);
}

int64_t linux_writev(interrupt_frame_t* f) {
    return transfer_vector(f, true);
}

static int64_t seek_to(program_file_t* file, int64_t offset, int whence) {
    int64_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? (int64_t)file->file->position : (int64_t)file_size(file);
    if (whence > SEEK_END) return -EINVAL;
    int64_t target = base + offset;
    if (target < 0 || target > FS_MAX_FILE_SIZE) return -EINVAL;
    // Seeking past the end is allowed, the next write fills the gap with zeros
    file->file->position = (uint32_t)target;
    return target;
}

int64_t linux_lseek(interrupt_frame_t* f) {
    program_file_t* file = program_fd_get((int64_t)ARG0(f));
    if (!file) return -EBADF;
    if (file->type != HANDLE_FILE) return -ESPIPE;
    return seek_to(file, (int64_t)ARG1(f), (int)ARG2(f));
}

static int64_t positioned(interrupt_frame_t* f, bool write) {
    program_file_t* file = program_fd_get((int64_t)ARG0(f));
    if (!file) return -EBADF;
    if (file->type != HANDLE_FILE) return -ESPIPE;
    uint32_t saved = file->file->position;
    int64_t r = seek_to(file, (int64_t)ARG3(f), SEEK_SET);
    if (r >= 0) r = write ? write_fd((int64_t)ARG0(f), ARG1(f), ARG2(f)) : read_fd((int64_t)ARG0(f), ARG1(f), ARG2(f));
    file->file->position = saved;
    return r;
}

int64_t linux_pread(interrupt_frame_t* f) {
    return positioned(f, false);
}

int64_t linux_pwrite(interrupt_frame_t* f) {
    return positioned(f, true);
}

int64_t linux_file_read_at(int64_t fd, uint64_t buffer, uint64_t length, uint64_t offset) {
    program_file_t* file = program_fd_get(fd);
    if (!file) return -EBADF;
    if (file->type != HANDLE_FILE) return -ENODEV;
    uint32_t saved = file->file->position;
    file->file->position = (uint32_t)offset;
    int64_t n = filesystem_read_file(file->file, (void*)(uintptr_t)buffer, (uint32_t)length);
    file->file->position = saved;
    return n;
}

int64_t linux_fsync(interrupt_frame_t* f) {
    return program_fd_get((int64_t)ARG0(f)) ? 0 : -EBADF;
}

int64_t linux_ftruncate(interrupt_frame_t* f) {
    program_file_t* file = program_fd_get((int64_t)ARG0(f));
    if (!file) return -EBADF;
    if (file->type != HANDLE_FILE || (file->flags & O_ACCMODE) == O_RDONLY) return -EINVAL;
    if ((int64_t)ARG1(f) < 0 || ARG1(f) > FS_MAX_FILE_SIZE) return -EFBIG;
    return filesystem_truncate_file(file->path, (uint32_t)ARG1(f)) ? 0 : -ENOSPC;
}

/* access checks */

static int64_t check_access(const char* path, uint64_t mode) {
    fs_file_info_t info;
    if (!filesystem_get_file_info(path, &info)) return -ENOENT;
    if ((mode & R_OK) && !(info.permissions & FS_PERM_READ)) return -EACCES;
    if ((mode & W_OK) && !(info.permissions & FS_PERM_WRITE)) return -EACCES;
    bool executable = info.type == FS_TYPE_DIRECTORY || (info.permissions & FS_PERM_EXECUTE);
    if ((mode & X_OK) && !executable) return -EACCES;
    return 0;
}

int64_t linux_access(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    if (copy_path(ARG0(f), path) < 0) return -EFAULT;
    return check_access(path, ARG1(f));
}

int64_t linux_faccessat(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    int64_t r = resolve_at((int64_t)ARG0(f), ARG1(f), path);
    return r < 0 ? r : check_access(path, ARG2(f));
}

/* terminal control */

static int64_t set_termios(uint64_t user) {
    linux_termios_t t;
    if (!user_copy_in(&t, user, sizeof(t))) return -EFAULT;
    termios = t;
    console_set_mode(t.lflag & TERMIOS_ICANON, t.lflag & TERMIOS_ECHO, t.lflag & TERMIOS_ISIG);
    return 0;
}

int64_t linux_ioctl(interrupt_frame_t* f) {
    program_file_t* file = program_fd_get((int64_t)ARG0(f));
    if (!file) return -EBADF;
    bool tty = file->type == HANDLE_CONSOLE_IN || file->type == HANDLE_CONSOLE_OUT;
    if (!tty) return -ENOTTY;
    linux_winsize_t size = {CONSOLE_ROWS, CONSOLE_COLS, 0, 0};
    int32_t pending = (int32_t)console_pending();
    int32_t group = (int32_t)program.pid;
    switch (ARG1(f)) {
        case TCGETS: return user_copy_out(ARG2(f), &termios, sizeof(termios)) ? 0 : -EFAULT;
        case TCSETS: case TCSETSW: case TCSETSF: return set_termios(ARG2(f));
        case TIOCGWINSZ: return user_copy_out(ARG2(f), &size, sizeof(size)) ? 0 : -EFAULT;
        case FIONREAD: return user_copy_out(ARG2(f), &pending, sizeof(pending)) ? 0 : -EFAULT;
        case TIOCGPGRP: return user_copy_out(ARG2(f), &group, sizeof(group)) ? 0 : -EFAULT;
        default: return -ENOTTY;
    }
}

/* descriptors */

int64_t linux_fcntl(interrupt_frame_t* f) {
    int64_t fd = (int64_t)ARG0(f);
    program_file_t* file = program_fd_get(fd);
    if (!file) return -EBADF;
    switch (ARG1(f)) {
        case F_DUPFD:
        case F_DUPFD_CLOEXEC: {
            int r = program_fd_dup(fd, (int64_t)ARG2(f));
            return r < 0 ? -EMFILE : r;
        }
        // Close on exec has no effect, Apollo programs cannot exec
        case F_GETFD: return 0;
        case F_SETFD: return 0;
        case F_GETFL: return file->flags;
        case F_SETFL:
            file->flags = (file->flags & ~(uint32_t)(O_APPEND | O_NONBLOCK)) | ((uint32_t)ARG2(f) & (O_APPEND | O_NONBLOCK));
            return 0;
        default: return -EINVAL;
    }
}

int64_t linux_dup(interrupt_frame_t* f) {
    if (!program_fd_get((int64_t)ARG0(f))) return -EBADF;
    int r = program_fd_dup((int64_t)ARG0(f), 0);
    return r < 0 ? -EMFILE : r;
}

int64_t linux_dup2(interrupt_frame_t* f) {
    if ((int64_t)ARG1(f) < 0 || ARG1(f) >= PROGRAM_MAX_HANDLES) return -EBADF;
    return program_fd_dup_to((int64_t)ARG0(f), (int64_t)ARG1(f)) ? (int64_t)ARG1(f) : -EBADF;
}

int64_t linux_dup3(interrupt_frame_t* f) {
    if (ARG0(f) == ARG1(f)) return -EINVAL;
    return linux_dup2(f);
}

/* directories */

static uint32_t emit_dirent(uint8_t* out, uint32_t space, const char* name, uint8_t type, uint64_t offset) {
    uint32_t name_length = string_length(name);
    uint32_t record = ALIGN_UP(DIRENT_HEADER + name_length + 1, DIRENT_ALIGN);
    if (record > space) return 0;
    memset(out, 0, record);
    *(uint64_t*)out = path_inode(name);
    *(uint64_t*)(out + 8) = offset;
    *(uint16_t*)(out + 16) = (uint16_t)record;
    out[18] = type;
    memcpy(out + DIRENT_HEADER, name, name_length + 1);
    return record;
}

// Index 0 and 1 are . and .., the directory's entries follow
int64_t linux_getdents64(interrupt_frame_t* f) {
    program_file_t* dir = program_fd_get((int64_t)ARG0(f));
    if (!dir) return -EBADF;
    if (dir->type != HANDLE_DIRECTORY) return -ENOTDIR;
    if (!user_check(ARG1(f), ARG2(f), true)) return -EFAULT;
    uint32_t count = filesystem_list_directory(dir->path, directory_entries, DIRECTORY_SCAN_MAX);
    uint8_t* out = (uint8_t*)(uintptr_t)ARG1(f);
    uint32_t used = 0;
    while (true) {
        uint32_t index = dir->directory_index;
        if (index >= count + 2) break;
        const char* name = index == 0 ? "." : index == 1 ? ".." : directory_entries[index - 2].name;
        uint8_t type = index < 2 || directory_entries[index - 2].type == FS_TYPE_DIRECTORY ? DT_DIR : DT_REG;
        // The root directory is listed as its own child, skip that entry
        if (index >= 2 && string_equals(name, "/")) { dir->directory_index++; continue; }
        uint32_t n = emit_dirent(out + used, (uint32_t)ARG2(f) - used, name, type, index + 1);
        if (n == 0) break;
        used += n;
        dir->directory_index++;
    }
    if (used == 0 && dir->directory_index < count + 2) return -EINVAL;
    return used;
}

int64_t linux_getcwd(interrupt_frame_t* f) {
    char cwd[FS_MAX_PATH_LENGTH];
    if (!filesystem_get_current_directory(cwd, sizeof(cwd))) return -ENOENT;
    uint64_t length = string_length(cwd) + 1;
    if (length > ARG1(f)) return -ERANGE;
    return user_copy_out(ARG0(f), cwd, length) ? (int64_t)length : -EFAULT;
}

int64_t linux_chdir(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    if (copy_path(ARG0(f), path) < 0) return -EFAULT;
    fs_file_info_t info;
    if (!filesystem_get_file_info(path, &info)) return -ENOENT;
    if (info.type != FS_TYPE_DIRECTORY) return -ENOTDIR;
    return filesystem_change_directory(path) ? 0 : -ENOENT;
}

static int64_t make_directory(const char* path) {
    if (filesystem_file_exists(path)) return -EEXIST;
    return filesystem_create_directory(path) ? 0 : -ENOENT;
}

int64_t linux_mkdir(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    if (copy_path(ARG0(f), path) < 0) return -EFAULT;
    return make_directory(path);
}

int64_t linux_mkdirat(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    int64_t r = resolve_at((int64_t)ARG0(f), ARG1(f), path);
    return r < 0 ? r : make_directory(path);
}

static int64_t remove_path(const char* path, bool directory) {
    fs_file_info_t info;
    if (!filesystem_get_file_info(path, &info)) return -ENOENT;
    if (directory && info.type != FS_TYPE_DIRECTORY) return -ENOTDIR;
    if (!directory && info.type == FS_TYPE_DIRECTORY) return -EISDIR;
    if (directory) return filesystem_remove_directory(path) ? 0 : -ENOTEMPTY;
    return filesystem_delete_file(path) ? 0 : -EIO;
}

int64_t linux_rmdir(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    if (copy_path(ARG0(f), path) < 0) return -EFAULT;
    return remove_path(path, true);
}

int64_t linux_unlink(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    if (copy_path(ARG0(f), path) < 0) return -EFAULT;
    return remove_path(path, false);
}

int64_t linux_unlinkat(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    int64_t r = resolve_at((int64_t)ARG0(f), ARG1(f), path);
    return r < 0 ? r : remove_path(path, (ARG2(f) & AT_REMOVEDIR) != 0);
}

static int64_t rename_path(const char* from, const char* to) {
    fs_file_info_t info;
    if (!filesystem_get_file_info(from, &info)) return -ENOENT;
    if (info.type == FS_TYPE_DIRECTORY) return -EISDIR;
    if (filesystem_file_exists(to) && !filesystem_delete_file(to)) return -EISDIR;
    return filesystem_move_file(from, to) ? 0 : -ENOSPC;
}

int64_t linux_rename(interrupt_frame_t* f) {
    char from[FS_MAX_PATH_LENGTH];
    char to[FS_MAX_PATH_LENGTH];
    if (copy_path(ARG0(f), from) < 0 || copy_path(ARG1(f), to) < 0) return -EFAULT;
    return rename_path(from, to);
}

int64_t linux_renameat(interrupt_frame_t* f) {
    char from[FS_MAX_PATH_LENGTH];
    char to[FS_MAX_PATH_LENGTH];
    int64_t r = resolve_at((int64_t)ARG0(f), ARG1(f), from);
    if (r == 0) r = resolve_at((int64_t)ARG2(f), ARG3(f), to);
    return r < 0 ? r : rename_path(from, to);
}

// The only link Apollo has is /proc/self/exe, which names the running program
static int64_t read_link(const char* path, uint64_t buffer, uint64_t size) {
    if (!string_equals(path, "/proc/self/exe")) return filesystem_file_exists(path) ? -EINVAL : -ENOENT;
    uint64_t length = string_length(program.path);
    if (length > size) length = size;
    return user_copy_out(buffer, program.path, length) ? (int64_t)length : -EFAULT;
}

int64_t linux_readlink(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    if (copy_path(ARG0(f), path) < 0) return -EFAULT;
    return read_link(path, ARG1(f), ARG2(f));
}

int64_t linux_readlinkat(interrupt_frame_t* f) {
    char path[FS_MAX_PATH_LENGTH];
    int64_t r = resolve_at((int64_t)ARG0(f), ARG1(f), path);
    return r < 0 ? r : read_link(path, ARG2(f), ARG3(f));
}
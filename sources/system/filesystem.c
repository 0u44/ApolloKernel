#include "filesystem.h"
#include "heap_allocator.h"
#include "time_keeper.h"
#include "executor.h"
#include "memory.h"
#include "types.h"


typedef struct {
    fs_file_info_t files[FS_MAX_FILES];
    uint32_t used_pages;
    uint32_t current_directory_id;
    bool is_initialized;
    uint32_t next_file_id;
} filesystem_state_t;

static filesystem_state_t fs_state = {0};

static uint32_t string_length(const char* str) {
    uint32_t len = 0;
    while (str && str[len] != '\0') len++;
    return len;
}

static int string_compare(const char* str1, const char* str2) {
    while (*str1 && *str2 && *str1 == *str2) {
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

static void string_append(char* dest, const char* src) {
    while (*dest) dest++;
    while (*src) *dest++ = *src++;
    *dest = '\0';
}

static void memory_copy(void* dest, const void* src, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < size; i++) {
        d[i] = s[i];
    }
}

static void memory_set(void* dest, uint8_t value, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) {
        d[i] = value;
    }
}

static uint32_t get_current_time(void) {
    return (uint32_t)time_keeper_get_unix_time();
}

static void release_storage(fs_file_info_t* file) {
    if (file->data) frame_free_contiguous((uint64_t)(uintptr_t)file->data, file->capacity_pages);
    fs_state.used_pages -= file->capacity_pages;
    file->data = NULL;
    file->capacity_pages = 0;
}

// File data lives in one run of pages, doubled when a write passes the end
static bool ensure_capacity(fs_file_info_t* file, uint32_t bytes) {
    if (bytes <= file->capacity_pages * PAGE_SIZE) return true;
    if (bytes > FS_MAX_FILE_SIZE) return false;
    uint32_t pages = ALIGN_UP(bytes, PAGE_SIZE) / PAGE_SIZE;
    if (pages < file->capacity_pages * 2) pages = file->capacity_pages * 2;
    if (pages * PAGE_SIZE > FS_MAX_FILE_SIZE) pages = FS_MAX_FILE_SIZE / PAGE_SIZE;
    uint8_t* data = (uint8_t*)(uintptr_t)frame_alloc_contiguous(pages);
    if (!data) return false;
    if (file->data) memory_copy(data, file->data, file->size);
    uint32_t size = file->size;
    release_storage(file);
    file->data = data;
    file->capacity_pages = pages;
    file->size = size;
    fs_state.used_pages += pages;
    return true;
}

static uint32_t allocate_file_id(void) {
    for (uint32_t i = 2; i < FS_MAX_FILES; i++) {
        if (!fs_state.files[i].is_valid) {
            return i;
        }
    }
    return 0;
}

static void extract_filename(const char* path, char* filename) {
    const char* last_slash = path;
    const char* current = path;

    while (*current) {
        if (*current == '/') {
            last_slash = current + 1;
        }
        current++;
    }

    string_copy(filename, last_slash);
}

static void extract_directory(const char* path, char* directory) {
    const char* last_slash = NULL;
    const char* current = path;

    while (*current) {
        if (*current == '/') {
            last_slash = current;
        }
        current++;
    }

    if (last_slash) {
        uint32_t len = last_slash - path;
        for (uint32_t i = 0; i < len && i < FS_MAX_PATH_LENGTH - 1; i++) {
            directory[i] = path[i];
        }
        directory[len] = '\0';
        if (len == 0) {
            string_copy(directory, "/");
        }
    } else {
        // A bare name lives in the current directory, which the empty path resolves to
        directory[0] = '\0';
    }
}

static uint32_t find_file_in_directory(uint32_t dir_id, const char* name) {
    for (uint32_t i = 1; i < FS_MAX_FILES; i++) {
        if (fs_state.files[i].is_valid &&
            fs_state.files[i].parent_id == dir_id &&
            string_compare(fs_state.files[i].name, name) == 0) {
            return i;
        }
    }
    return 0;
}

static uint32_t resolve_path_to_id(const char* path) {
    if (!path || string_length(path) == 0) {
        return fs_state.current_directory_id;
    }

    uint32_t current_id;

    if (path[0] == '/') {
        current_id = 1;
        path++;
    } else {
        current_id = fs_state.current_directory_id;
    }

    if (string_length(path) == 0) {
        return current_id;
    }

    char component[FS_MAX_FILENAME_LENGTH];
    uint32_t comp_pos = 0;

    while (*path) {
        if (*path == '/') {
            if (comp_pos > 0) {
                component[comp_pos] = '\0';

                if (string_compare(component, ".") == 0) {
                } else if (string_compare(component, "..") == 0) {
                    if (current_id != 1) {
                        current_id = fs_state.files[current_id].parent_id;
                    }
                } else {
                    uint32_t found_id = find_file_in_directory(current_id, component);
                    if (found_id == 0) {
                        return 0;
                    }
                    current_id = found_id;
                }
                comp_pos = 0;
            }
        } else {
            if (comp_pos < FS_MAX_FILENAME_LENGTH - 1) {
                component[comp_pos++] = *path;
            }
        }
        path++;
    }

    if (comp_pos > 0) {
        component[comp_pos] = '\0';

        if (string_compare(component, ".") == 0) {
        } else if (string_compare(component, "..") == 0) {
            if (current_id != 1) {
                current_id = fs_state.files[current_id].parent_id;
            }
        } else {
            uint32_t found_id = find_file_in_directory(current_id, component);
            if (found_id == 0) {
                return 0;
            }
            current_id = found_id;
        }
    }

    return current_id;
}

static void write_file_content(uint32_t file_id, const char* content) {
    if (file_id == 0 || !fs_state.files[file_id].is_valid ||
        fs_state.files[file_id].type != FS_TYPE_FILE) {
        return;
    }

    uint32_t content_len = string_length(content);
    fs_file_info_t* file = &fs_state.files[file_id];
    if (!ensure_capacity(file, content_len)) return;
    memory_copy(file->data, content, content_len);
    file->size = content_len;
    file->modified_time = get_current_time();
}

static void create_system_files(void) {
    uint32_t readme_id = find_file_in_directory(
        find_file_in_directory(1, "home"), "readme.txt");
    if (readme_id != 0) {
        const char* readme_content =
            "Welcome to Apollo Operating System!\n\n"
            "This is a fully functional x86_64 kernel with:\n"
            "- Complete file system implementation\n"
            "- Text editor with real file I/O\n"
            "- Memory management\n"
            "- Kernel task accounting (ps)\n"
            "- C subset compiler (acc) and bytecode runner (exec)\n\n"
            "Commands to try:\n"
            "- ls        List files\n"
            "- cd        Change directory\n"
            "- cat       View file contents\n"
            "- edit      Edit files\n"
            "- mkdir     Create directories\n"
            "- touch     Create files\n"
            "- cp        Copy files\n"
            "- mv        Move files\n"
            "- find      Search files\n"
            "- grep      Search text\n"
            "- tree      Directory structure\n"
            "- help      All commands\n\n"
            "Apollo Kernel v1.0 - Built with modern C and Assembly\n";
        write_file_content(readme_id, readme_content);
    }

    uint32_t sample_id = find_file_in_directory(
        find_file_in_directory(1, "home"), "sample.c");
    if (sample_id != 0) {
        const char* sample_content =
            "/*\n"
            " * Apollo Operating System\n"
            " */\n\n"
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n\n"
            "int main(void) {\n"
            "    printf(\"Hello from Apollo OS!\\n\");\n"
            "    printf(\"This kernel supports:\\n\");\n"
            "    printf(\"- Full file system\\n\");\n"
            "    printf(\"- Memory management\\n\");\n"
            "    printf(\"- Process management\\n\");\n"
            "    printf(\"- Hardware drivers\\n\");\n"
            "    \n"
            "    // Example of file operations\n"
            "    FILE* fp = fopen(\"/tmp/output.txt\", \"w\");\n"
            "    if (fp) {\n"
            "        fprintf(fp, \"File I/O works!\\n\");\n"
            "        fclose(fp);\n"
            "    }\n"
            "    \n"
            "    return 0;\n"
            "}\n\n"
            "/*\n"
            " * Compile with: acc sample.c sample.o\n"
            " * Run with: exec sample.o\n"
            " */\n";
        write_file_content(sample_id, sample_content);
    }

    executor_write_native("/bin/blackjack", "blackjack");
    executor_write_native("/bin/roulette", "roulette");

    uint32_t dev_dir = find_file_in_directory(1, "dev");
    if (dev_dir != 0) {
        if (filesystem_create_file("/dev/version")) {
            uint32_t version_id = find_file_in_directory(dev_dir, "version");
            if (version_id != 0) {
                const char* version_content =
                    "Apollo Operating System v1.0\n"
                    "Kernel Build: " __DATE__ " " __TIME__ "\n"
                    "Architecture: x86_64\n"
                    "Compiler: " __VERSION__ "\n"
                    "Features: long mode, 4GB identity map, in-memory file system, no SSE\n";
                write_file_content(version_id, version_content);
            }
        }
    }
}

void filesystem_initialize(void) {
    if (fs_state.is_initialized) return;

    for (uint32_t i = 0; i < FS_MAX_FILES; i++) {
        fs_state.files[i].is_valid = false;
    }

    fs_state.used_pages = 0;


    fs_state.files[1].is_valid = true;
    string_copy(fs_state.files[1].name, "/");
    fs_state.files[1].type = FS_TYPE_DIRECTORY;
    fs_state.files[1].size = 0;
    fs_state.files[1].created_time = get_current_time();
    fs_state.files[1].modified_time = fs_state.files[1].created_time;
    fs_state.files[1].permissions = FS_PERM_READ | FS_PERM_WRITE | FS_PERM_EXECUTE;
    fs_state.files[1].parent_id = 1;
    fs_state.files[1].data = NULL;
    fs_state.files[1].capacity_pages = 0;

    fs_state.current_directory_id = 1;
    fs_state.next_file_id = 2;
    fs_state.is_initialized = true;

    filesystem_create_directory("/home");
filesystem_create_directory("/bin");
    filesystem_create_directory("/etc");
    filesystem_create_directory("/tmp");
    filesystem_create_directory("/dev");
    filesystem_create_directory("/var");
    filesystem_create_directory("/var/log");
    filesystem_create_directory("/usr");
    filesystem_create_directory("/usr/bin");

    filesystem_create_file("/home/readme.txt");
    filesystem_create_file("/home/sample.c");

    create_system_files();
}

bool filesystem_create_directory(const char* path) {
    if (!path || string_length(path) == 0) return false;

    char parent_path[FS_MAX_PATH_LENGTH];
    char dirname[FS_MAX_FILENAME_LENGTH];

    extract_directory(path, parent_path);
    extract_filename(path, dirname);

    uint32_t parent_id = resolve_path_to_id(parent_path);
    if (parent_id == 0 || fs_state.files[parent_id].type != FS_TYPE_DIRECTORY) {
        return false;
    }

    if (find_file_in_directory(parent_id, dirname) != 0) {
        return false;
    }

    uint32_t new_id = allocate_file_id();
    if (new_id == 0) return false;

    fs_state.files[new_id].is_valid = true;
    string_copy(fs_state.files[new_id].name, dirname);
    fs_state.files[new_id].type = FS_TYPE_DIRECTORY;
    fs_state.files[new_id].size = 0;
    fs_state.files[new_id].created_time = get_current_time();
    fs_state.files[new_id].modified_time = fs_state.files[new_id].created_time;
    fs_state.files[new_id].permissions = FS_PERM_READ | FS_PERM_WRITE | FS_PERM_EXECUTE;
    fs_state.files[new_id].parent_id = parent_id;
    fs_state.files[new_id].data = NULL;
    fs_state.files[new_id].capacity_pages = 0;

    return true;
}

bool filesystem_create_file(const char* path) {
    if (!path || string_length(path) == 0) return false;

    char parent_path[FS_MAX_PATH_LENGTH];
    char filename[FS_MAX_FILENAME_LENGTH];

    extract_directory(path, parent_path);
    extract_filename(path, filename);

    uint32_t parent_id = resolve_path_to_id(parent_path);
    if (parent_id == 0 || fs_state.files[parent_id].type != FS_TYPE_DIRECTORY) {
        return false;
    }

    if (find_file_in_directory(parent_id, filename) != 0) {
        return false;
    }

    uint32_t new_id = allocate_file_id();
    if (new_id == 0) return false;

    fs_state.files[new_id].is_valid = true;
    string_copy(fs_state.files[new_id].name, filename);
    fs_state.files[new_id].type = FS_TYPE_FILE;
    fs_state.files[new_id].size = 0;
    fs_state.files[new_id].created_time = get_current_time();
    fs_state.files[new_id].modified_time = fs_state.files[new_id].created_time;
    fs_state.files[new_id].permissions = FS_PERM_READ | FS_PERM_WRITE;
    fs_state.files[new_id].parent_id = parent_id;
    fs_state.files[new_id].data = NULL;
    fs_state.files[new_id].capacity_pages = 0;

    return true;
}

// Directories go through filesystem_remove_directory
bool filesystem_delete_file(const char* path) {
    uint32_t file_id = resolve_path_to_id(path);
    if (file_id == 0 || fs_state.files[file_id].type != FS_TYPE_FILE) return false;

    release_storage(&fs_state.files[file_id]);

    fs_state.files[file_id].is_valid = false;

    return true;
}

bool filesystem_change_directory(const char* path) {
    uint32_t dir_id = resolve_path_to_id(path);
    if (dir_id == 0 || fs_state.files[dir_id].type != FS_TYPE_DIRECTORY) {
        return false;
    }

    fs_state.current_directory_id = dir_id;
    return true;
}

#define FS_ROOT_ID 1
#define FS_MAX_DEPTH 32

// Walks parent links from an entry up to the root and writes the absolute path
static bool path_from_id(uint32_t id, char* buffer, uint32_t buffer_size) {
    if (!buffer || buffer_size < 2) return false;
    uint32_t chain[FS_MAX_DEPTH];
    uint32_t depth = 0;
    while (id != FS_ROOT_ID && depth < FS_MAX_DEPTH) {
        chain[depth++] = id;
        id = fs_state.files[id].parent_id;
    }
    if (id != FS_ROOT_ID) return false;
    buffer[0] = '/';
    buffer[1] = '\0';
    for (int32_t i = (int32_t)depth - 1; i >= 0; i--) {
        const char* name = fs_state.files[chain[i]].name;
        if (string_length(buffer) + string_length(name) + 2 > buffer_size) return false;
        string_append(buffer, name);
        if (i > 0) string_append(buffer, "/");
    }
    return true;
}

bool filesystem_get_current_directory(char* buffer, uint32_t buffer_size) {
    return path_from_id(fs_state.current_directory_id, buffer, buffer_size);
}

bool filesystem_resolve_path(const char* path, char* resolved_path, uint32_t buffer_size) {
    uint32_t id = resolve_path_to_id(path);
    return id != 0 && path_from_id(id, resolved_path, buffer_size);
}

static bool is_ancestor_or_self(uint32_t candidate, uint32_t id) {
    for (uint32_t depth = 0; depth < FS_MAX_DEPTH; depth++) {
        if (id == candidate) return true;
        if (id == FS_ROOT_ID) return false;
        id = fs_state.files[id].parent_id;
    }
    return false;
}

static bool directory_is_empty(uint32_t dir_id) {
    for (uint32_t i = 1; i < FS_MAX_FILES; i++) {
        if (fs_state.files[i].is_valid && fs_state.files[i].parent_id == dir_id && i != dir_id) {
            return false;
        }
    }
    return true;
}

bool filesystem_remove_directory(const char* path) {
    uint32_t dir_id = resolve_path_to_id(path);
    if (dir_id == 0 || dir_id == FS_ROOT_ID || fs_state.files[dir_id].type != FS_TYPE_DIRECTORY) return false;
    if (!directory_is_empty(dir_id) || is_ancestor_or_self(dir_id, fs_state.current_directory_id)) return false;
    fs_state.files[dir_id].is_valid = false;
    return true;
}

bool filesystem_seek_file(fs_file_handle_t* handle, uint32_t position) {
    if (!handle || !handle->is_open) return false;
    uint32_t limit = handle->write_mode ? FS_MAX_FILE_SIZE : fs_state.files[handle->file_id].size;
    if (position > limit) return false;
    handle->position = position;
    return true;
}

// Shrinking keeps the pages, growing fills the new part with zeros
bool filesystem_truncate_file(const char* path, uint32_t size) {
    uint32_t file_id = resolve_path_to_id(path);
    if (file_id == 0 || fs_state.files[file_id].type != FS_TYPE_FILE) return false;
    fs_file_info_t* file = &fs_state.files[file_id];
    if (size > file->size) {
        if (!ensure_capacity(file, size)) return false;
        memory_set(file->data + file->size, 0, size - file->size);
    }
    file->size = size;
    file->modified_time = get_current_time();
    return true;
}

// Leaves only the root directory, every file's pages are released
void filesystem_format(void) {
    for (uint32_t i = 2; i < FS_MAX_FILES; i++) {
        if (fs_state.files[i].is_valid && fs_state.files[i].type == FS_TYPE_FILE) {
            release_storage(&fs_state.files[i]);
        }
        fs_state.files[i].is_valid = false;
    }
    fs_state.current_directory_id = FS_ROOT_ID;
    fs_state.files[FS_ROOT_ID].modified_time = get_current_time();
}

uint32_t filesystem_list_directory(const char* path, fs_dir_entry_t* entries, uint32_t max_entries) {
    uint32_t dir_id;

    if (path && string_length(path) > 0) {
        dir_id = resolve_path_to_id(path);
    } else {
        dir_id = fs_state.current_directory_id;
    }

    if (dir_id == 0 || fs_state.files[dir_id].type != FS_TYPE_DIRECTORY) {
        return 0;
    }

    uint32_t count = 0;

    for (uint32_t i = 1; i < FS_MAX_FILES && count < max_entries; i++) {
        if (fs_state.files[i].is_valid && fs_state.files[i].parent_id == dir_id) {
            string_copy(entries[count].name, fs_state.files[i].name);
            entries[count].type = fs_state.files[i].type;
            entries[count].size = fs_state.files[i].size;
            entries[count].permissions = fs_state.files[i].permissions;
            count++;
        }
    }

    return count;
}

bool filesystem_file_exists(const char* path) {
    return resolve_path_to_id(path) != 0;
}

bool filesystem_get_file_info(const char* path, fs_file_info_t* info) {
    uint32_t file_id = resolve_path_to_id(path);
    if (file_id == 0 || !info) return false;

    *info = fs_state.files[file_id];
    return true;
}

fs_file_handle_t* filesystem_open_file(const char* path, bool write_mode) {
    uint32_t file_id = resolve_path_to_id(path);
    if (file_id == 0 || fs_state.files[file_id].type != FS_TYPE_FILE) {
        return NULL;
    }

    fs_file_handle_t* handle = apollo_allocate_memory(sizeof(fs_file_handle_t));
    if (!handle) return NULL;

    handle->file_id = file_id;
    handle->position = 0;
    handle->is_open = true;
    handle->write_mode = write_mode;

    return handle;
}

void filesystem_close_file(fs_file_handle_t* handle) {
    if (handle) {
        handle->is_open = false;
        apollo_free_memory(handle);
    }
}

uint32_t filesystem_read_file(fs_file_handle_t* handle, void* buffer, uint32_t size) {
    if (!handle || !handle->is_open || !buffer) return 0;

    fs_file_info_t* file = &fs_state.files[handle->file_id];
    if (!file->data || handle->position >= file->size) return 0;

    uint32_t bytes_to_read = size;
    if (handle->position + bytes_to_read > file->size) {
        bytes_to_read = file->size - handle->position;
    }

    if (bytes_to_read == 0) return 0;

    uint8_t* src = file->data + handle->position;
    uint8_t* dest = (uint8_t*)buffer;

    memory_copy(dest, src, bytes_to_read);

    handle->position += bytes_to_read;
    return bytes_to_read;
}

uint32_t filesystem_write_file(fs_file_handle_t* handle, const void* buffer, uint32_t size) {
    if (!handle || !handle->is_open || !handle->write_mode || !buffer) return 0;

    fs_file_info_t* file = &fs_state.files[handle->file_id];
    uint32_t bytes_to_write = size;
    if (handle->position + bytes_to_write > FS_MAX_FILE_SIZE) {
        bytes_to_write = FS_MAX_FILE_SIZE - handle->position;
    }

    if (bytes_to_write == 0 || !ensure_capacity(file, handle->position + bytes_to_write)) return 0;
    // A seek past the end leaves a gap that reads back as zeros
    if (handle->position > file->size) memory_set(file->data + file->size, 0, handle->position - file->size);

    uint8_t* dest = file->data + handle->position;
    const uint8_t* src = (const uint8_t*)buffer;

    memory_copy(dest, src, bytes_to_write);

    handle->position += bytes_to_write;

    if (handle->position > file->size) {
        file->size = handle->position;
        file->modified_time = get_current_time();
    }

    return bytes_to_write;
}

bool filesystem_copy_file(const char* source, const char* destination) {
    uint32_t src_id = resolve_path_to_id(source);
    if (src_id == 0 || fs_state.files[src_id].type != FS_TYPE_FILE) {
        return false;
    }

    if (!filesystem_create_file(destination)) {
        return false;
    }

    fs_file_handle_t* src_handle = filesystem_open_file(source, false);
    fs_file_handle_t* dst_handle = filesystem_open_file(destination, true);

    if (!src_handle || !dst_handle) {
        if (src_handle) filesystem_close_file(src_handle);
        if (dst_handle) filesystem_close_file(dst_handle);
        return false;
    }

    uint8_t buffer[PAGE_SIZE];
    bool ok = true;
    uint32_t bytes_read;
    while (ok && (bytes_read = filesystem_read_file(src_handle, buffer, sizeof(buffer))) > 0) {
        ok = filesystem_write_file(dst_handle, buffer, bytes_read) == bytes_read;
    }

    filesystem_close_file(src_handle);
    filesystem_close_file(dst_handle);
    if (!ok) filesystem_delete_file(destination);
    return ok;
}

bool filesystem_move_file(const char* source, const char* destination) {
    if (!filesystem_copy_file(source, destination)) {
        return false;
    }

    return filesystem_delete_file(source);
}

// Files share free RAM with running programs
uint32_t filesystem_get_free_space(void) {
    return memory_free_frames() * PAGE_SIZE;
}

uint32_t filesystem_get_used_space(void) {
    return fs_state.used_pages * PAGE_SIZE;
}

bool filesystem_get_stats(fs_stats_t* stats) {
    if (!stats) return false;

    stats->total_files = 0;
    stats->total_directories = 0;

    for (uint32_t i = 1; i < FS_MAX_FILES; i++) {
        if (fs_state.files[i].is_valid) {
            if (fs_state.files[i].type == FS_TYPE_FILE) {
                stats->total_files++;
            } else {
                stats->total_directories++;
            }
        }
    }

    stats->used_pages = fs_state.used_pages;
    stats->free_pages = memory_free_frames();
    stats->total_space = (stats->used_pages + stats->free_pages) * PAGE_SIZE;
    stats->free_space = stats->free_pages * PAGE_SIZE;

    return true;
}

// Each boot module becomes a file under /boot that keeps the memory the loader put it in
uint32_t filesystem_add_boot_modules(void) {
    uint32_t added = 0;
    if (boot_module_count() == 0) return 0;
    if (!filesystem_file_exists(FS_BOOT_DIRECTORY)) filesystem_create_directory(FS_BOOT_DIRECTORY);
    for (uint32_t i = 0; i < boot_module_count(); i++) {
        uint8_t* data;
        uint32_t size;
        const char* name;
        char path[FS_MAX_PATH_LENGTH];
        boot_module_get(i, &data, &size, &name);
        string_copy(path, FS_BOOT_DIRECTORY "/");
        string_append(path, name);
        if (size > FS_MAX_FILE_SIZE || !filesystem_create_file(path)) continue;
        fs_file_info_t* file = &fs_state.files[resolve_path_to_id(path)];
        file->data = data;
        file->capacity_pages = ALIGN_UP(size, PAGE_SIZE) / PAGE_SIZE;
        file->size = size;
        file->permissions = FS_PERM_READ | FS_PERM_WRITE | FS_PERM_EXECUTE;
        fs_state.used_pages += file->capacity_pages;
        added++;
    }
    return added;
}

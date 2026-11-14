#include "runtime.h"

#define TEB_PAGES 2
#define TEB_STACK_BASE 0x08
#define TEB_STACK_LIMIT 0x10
#define TEB_SELF 0x30
#define TEB_PROCESS_ID 0x40
#define TEB_THREAD_ID 0x48
#define TEB_TLS_POINTER 0x58
#define TEB_PEB 0x60
#define TEB_LAST_ERROR 0x68
#define PEB_IMAGE_BASE 0x10
#define PEB_PARAMETERS 0x20
#define PEB_PROCESS_HEAP 0x30
#define PARAMETERS_IMAGE_PATH 0x60
#define PARAMETERS_COMMAND_LINE 0x70
#define PARAMETERS_ENVIRONMENT 0x80
#define PARAMETERS_SIZE 0x400
#define PAGE 4096
#define ARCH_SET_GS 0x1001
#define PROT_READ_WRITE 3
#define MAP_PRIVATE_ANONYMOUS 0x22
#define USER_STACK_TOP 0x00007FFFFFFFE000ULL
#define USER_STACK_RESERVE (8ULL * 1024 * 1024)
#define DOS_LFANEW 0x3C
#define OPTIONAL_HEADER_OFFSET 24
#define DIRECTORY_OFFSET 112
#define DIRECTORY_EXPORT 0
#define DIRECTORY_TLS 9
#define DIRECTORY_ENTRY_SIZE 8
#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1
#define PATH_LIMIT 256
#define MAX_ENVIRONMENT 128
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 0x4
#define RUNTIME_MODULE ((HMODULE)WIN32_RUNTIME_BASE)
#define STARTUP_INFO_SIZE 104
#define PF_XMMI_INSTRUCTIONS_AVAILABLE 6
#define PF_RDTSC_INSTRUCTION_AVAILABLE 8
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE 10
#define PF_SSE3_INSTRUCTIONS_AVAILABLE 13
#define PF_COMPARE_EXCHANGE128 14
#define CPUID_ECX_SSE3 (1u << 0)
#define CPUID_ECX_CX16 (1u << 13)

typedef DWORD (WINAPI *entry_point_t)(void* peb);
typedef void (WINAPI *tls_callback_t)(void* module, DWORD reason, void* reserved);

typedef struct {
    uint64_t start, end, index, callbacks;
    uint32_t zero_fill, characteristics;
} tls_directory_t;

static uint8_t* teb;
static uint8_t* peb;
static uint8_t* parameters;
static WCHAR* command_line_wide;
static char* command_line_ansi;
static WCHAR* environment[MAX_ENVIRONMENT];
static uint32_t environment_count;
static WCHAR module_path[PATH_LIMIT];
static uint64_t pointer_cookie;

void rt_set_last_error(DWORD error) {
    *(DWORD*)(teb + TEB_LAST_ERROR) = error;
}

DWORD rt_get_last_error(void) {
    return *(DWORD*)(teb + TEB_LAST_ERROR);
}

uint64_t rt_image_base(void) {
    return ((win32_runtime_header_t*)WIN32_RUNTIME_BASE)->image_base;
}

uint64_t rt_stack_base(void) {
    return USER_STACK_TOP;
}

uint64_t rt_stack_limit(void) {
    return USER_STACK_TOP - USER_STACK_RESERVE;
}

static void* map_zeroed(uint64_t length) {
    int64_t r = sys6(LINUX_MMAP, 0, length, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, (uint64_t)-1, 0);
    if (r < 0) rt_fatal("Win32 runtime: no memory for the process blocks", STATUS_NO_MEMORY);
    return (void*)r;
}

static void set_unicode_string(uint8_t* at, WCHAR* text) {
    uint16_t length = (uint16_t)(rt_wcslen(text) * sizeof(WCHAR));
    *(uint16_t*)at = length;
    *(uint16_t*)(at + 2) = (uint16_t)(length + sizeof(WCHAR));
    *(WCHAR**)(at + 8) = text;
}

static void build_blocks(void) {
    teb = map_zeroed(TEB_PAGES * PAGE);
    peb = map_zeroed(PAGE);
    parameters = map_zeroed(PARAMETERS_SIZE);
    *(uint64_t*)(teb + TEB_STACK_BASE) = rt_stack_base();
    *(uint64_t*)(teb + TEB_STACK_LIMIT) = rt_stack_limit();
    *(void**)(teb + TEB_SELF) = teb;
    *(uint64_t*)(teb + TEB_PROCESS_ID) = (uint64_t)sys0(LINUX_GETPID);
    *(uint64_t*)(teb + TEB_THREAD_ID) = (uint64_t)sys0(LINUX_GETTID);
    *(void**)(teb + TEB_PEB) = peb;
    *(uint64_t*)(peb + PEB_IMAGE_BASE) = rt_image_base();
    *(void**)(peb + PEB_PARAMETERS) = parameters;
    *(HANDLE*)(peb + PEB_PROCESS_HEAP) = rt_process_heap();
    sys2(LINUX_ARCH_PRCTL, ARCH_SET_GS, teb);
}

static WCHAR* widen(const char* text) {
    bool invalid = false;
    uint32_t length = (uint32_t)rt_strlen(text);
    uint32_t needed = rt_utf8_to_utf16(text, length, NULL, 0, &invalid);
    WCHAR* out = rt_alloc((needed + 1) * sizeof(WCHAR));
    if (!out) rt_fatal("Win32 runtime: no memory for the command line", STATUS_NO_MEMORY);
    rt_utf8_to_utf16(text, length, out, needed, &invalid);
    out[needed] = 0;
    return out;
}

static uint32_t quote_argument(const char* arg, char* out) {
    uint32_t n = 0;
    bool quote = arg[0] == '\0';
    for (const char* p = arg; *p; p++) if (*p == ' ' || *p == '\t' || *p == '"') quote = true;
    if (!quote) {
        for (const char* p = arg; *p; p++) if (out) out[n++] = *p; else n++;
        return n;
    }
    if (out) out[n] = '"';
    n++;
    uint32_t slashes = 0;
    for (const char* p = arg;; p++) {
        if (*p == '\\') { slashes++; continue; }
        uint32_t repeat = (*p == '"' || *p == '\0') ? slashes * 2 : slashes;
        for (uint32_t i = 0; i < repeat; i++) { if (out) out[n] = '\\'; n++; }
        slashes = 0;
        if (*p == '\0') break;
        if (*p == '"') { if (out) out[n] = '\\'; n++; }
        if (out) out[n] = *p;
        n++;
    }
    if (out) out[n] = '"';
    return n + 1;
}

static void build_command_line(int argc, char** argv) {
    uint32_t length = 0;
    for (int i = 0; i < argc; i++) length += quote_argument(argv[i], NULL) + 1;
    command_line_ansi = rt_alloc(length + 1);
    if (!command_line_ansi) rt_fatal("Win32 runtime: no memory for the command line", STATUS_NO_MEMORY);
    uint32_t at = 0;
    for (int i = 0; i < argc; i++) {
        at += quote_argument(argv[i], command_line_ansi + at);
        if (i + 1 < argc) command_line_ansi[at++] = ' ';
    }
    command_line_ansi[at] = '\0';
    command_line_wide = widen(command_line_ansi);
    set_unicode_string(parameters + PARAMETERS_COMMAND_LINE, command_line_wide);
}

static void build_environment(char** envp) {
    environment_count = 0;
    for (; *envp && environment_count < MAX_ENVIRONMENT; envp++) environment[environment_count++] = widen(*envp);
}

static void read_module_path(void) {
    char path[PATH_LIMIT];
    int64_t n = sys3(LINUX_READLINK, "/proc/self/exe", path, sizeof(path) - 1);
    path[n > 0 ? n : 0] = '\0';
    bool invalid = false;
    uint32_t w = rt_utf8_to_utf16(path, (uint32_t)rt_strlen(path), module_path, PATH_LIMIT - 1, &invalid);
    module_path[w < PATH_LIMIT ? w : PATH_LIMIT - 1] = 0;
    set_unicode_string(parameters + PARAMETERS_IMAGE_PATH, module_path);
}

static const uint32_t* image_directory(uint64_t base, uint32_t index) {
    uint32_t lfanew = *(const uint32_t*)(base + DOS_LFANEW);
    return (const uint32_t*)(base + lfanew + OPTIONAL_HEADER_OFFSET + DIRECTORY_OFFSET + index * DIRECTORY_ENTRY_SIZE);
}

static void setup_tls(void) {
    const uint32_t* dir = image_directory(rt_image_base(), DIRECTORY_TLS);
    if (dir[1] == 0) return;
    const tls_directory_t* tls = (const tls_directory_t*)(rt_image_base() + dir[0]);
    uint64_t template_size = tls->end - tls->start;
    uint8_t* block = rt_alloc_zero(template_size + tls->zero_fill);
    void** array = rt_alloc_zero(sizeof(void*));
    if (!block || !array) rt_fatal("Win32 runtime: no memory for thread local storage", STATUS_NO_MEMORY);
    memcpy(block, (const void*)tls->start, template_size);
    array[0] = block;
    *(void***)(teb + TEB_TLS_POINTER) = array;
    if (tls->index) *(uint32_t*)tls->index = 0;
}

void rt_run_tls_callbacks(DWORD reason) {
    const uint32_t* dir = image_directory(rt_image_base(), DIRECTORY_TLS);
    if (dir[1] == 0) return;
    const tls_directory_t* tls = (const tls_directory_t*)(rt_image_base() + dir[0]);
    if (!tls->callbacks) return;
    for (tls_callback_t* cb = (tls_callback_t*)tls->callbacks; *cb; cb++) (*cb)((void*)rt_image_base(), reason, NULL);
}

__asm__(
    ".text\n"
    ".globl runtime_entry\n"
    "runtime_entry:\n"
    "    mov %rsp, %rdi\n"
    "    and $-16, %rsp\n"
    "    call runtime_start\n"
    "    ud2\n");

__attribute__((used, noreturn)) void runtime_start(uint64_t* stack) {
    int argc = (int)stack[0];
    char** argv = (char**)(stack + 1);
    char** envp = argv + argc + 1;
    rt_heap_initialize();
    build_blocks();
    sys4(LINUX_GETRANDOM, &pointer_cookie, sizeof(pointer_cookie), 0, 0);
    build_command_line(argc, argv);
    build_environment(envp);
    read_module_path();
    rt_files_initialize();
    rt_exceptions_initialize();
    setup_tls();
    rt_run_tls_callbacks(DLL_PROCESS_ATTACH);
    uint32_t lfanew = *(const uint32_t*)(rt_image_base() + DOS_LFANEW);
    uint32_t entry = *(const uint32_t*)(rt_image_base() + lfanew + OPTIONAL_HEADER_OFFSET + 16);
    DWORD code = ((entry_point_t)(rt_image_base() + entry))(peb);
    rt_run_tls_callbacks(DLL_PROCESS_DETACH);
    rt_exit(code);
}

WINAPI void ExitProcess(UINT code) {
    rt_run_tls_callbacks(DLL_PROCESS_DETACH);
    rt_exit(code);
}

WINAPI BOOL TerminateProcess(HANDLE process, UINT code) {
    if (process != CURRENT_PROCESS_HANDLE) {
        rt_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    rt_exit(code);
}

WINAPI HANDLE GetCurrentProcess(void) {
    return CURRENT_PROCESS_HANDLE;
}

WINAPI DWORD GetCurrentProcessId(void) {
    return (DWORD)*(uint64_t*)(teb + TEB_PROCESS_ID);
}

WINAPI DWORD GetCurrentThreadId(void) {
    return (DWORD)*(uint64_t*)(teb + TEB_THREAD_ID);
}

WINAPI DWORD GetLastError(void) {
    return rt_get_last_error();
}

WINAPI void SetLastError(DWORD error) {
    rt_set_last_error(error);
}

WINAPI char* GetCommandLineA(void) {
    return command_line_ansi;
}

WINAPI WCHAR* GetCommandLineW(void) {
    return command_line_wide;
}

WINAPI void GetStartupInfoW(void* info) {
    memset(info, 0, STARTUP_INFO_SIZE);
    *(DWORD*)info = STARTUP_INFO_SIZE;
}

WINAPI BOOL IsDebuggerPresent(void) {
    return FALSE;
}

static uint32_t cpuid_ecx(void) {
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    return c;
}

WINAPI BOOL IsProcessorFeaturePresent(DWORD feature) {
    switch (feature) {
        case PF_XMMI_INSTRUCTIONS_AVAILABLE:
        case PF_XMMI64_INSTRUCTIONS_AVAILABLE:
        case PF_RDTSC_INSTRUCTION_AVAILABLE: return TRUE;
        case PF_SSE3_INSTRUCTIONS_AVAILABLE: return (cpuid_ecx() & CPUID_ECX_SSE3) != 0;
        case PF_COMPARE_EXCHANGE128: return (cpuid_ecx() & CPUID_ECX_CX16) != 0;
        default: return FALSE;
    }
}

static uint64_t rotate(uint64_t value, uint32_t bits) {
    bits &= 63;
    return bits ? (value >> bits) | (value << (64 - bits)) : value;
}

WINAPI void* EncodePointer(void* pointer) {
    return (void*)rotate((uint64_t)pointer ^ pointer_cookie, (uint32_t)(pointer_cookie & 63));
}

WINAPI void* DecodePointer(void* pointer) {
    return (void*)(rotate((uint64_t)pointer, 64 - (uint32_t)(pointer_cookie & 63)) ^ pointer_cookie);
}

WINAPI void InitializeSListHead(void* head) {
    memset(head, 0, 16);
}

static bool kernel32_name(const char* name) {
    char head[17];
    uint32_t i = 0;
    while (name[i] && i < sizeof(head) - 1) { head[i] = name[i]; i++; }
    head[i] = '\0';
    return rt_names_equal(name, "kernel32.dll") || rt_names_equal(name, "kernel32") || rt_names_equal(head, "api-ms-win-core-");
}

static bool kernel32_wide(const WCHAR* name) {
    char narrow[PATH_LIMIT];
    bool invalid = false;
    uint32_t n = rt_utf16_to_utf8(name, (uint32_t)rt_wcslen(name), narrow, sizeof(narrow) - 1, &invalid);
    narrow[n < sizeof(narrow) ? n : sizeof(narrow) - 1] = '\0';
    return kernel32_name(narrow);
}

static HMODULE module_for_address(uint64_t address) {
    const win32_runtime_header_t* runtime = (const win32_runtime_header_t*)WIN32_RUNTIME_BASE;
    if (address >= WIN32_RUNTIME_BASE && address < runtime->end) return RUNTIME_MODULE;
    uint32_t lfanew = *(const uint32_t*)(rt_image_base() + DOS_LFANEW);
    uint32_t size = *(const uint32_t*)(rt_image_base() + lfanew + OPTIONAL_HEADER_OFFSET + 56);
    if (address >= rt_image_base() && address < rt_image_base() + size) return (HMODULE)rt_image_base();
    return NULL;
}

WINAPI HMODULE GetModuleHandleW(const WCHAR* name) {
    if (!name) return (HMODULE)rt_image_base();
    if (kernel32_wide(name)) return RUNTIME_MODULE;
    rt_set_last_error(ERROR_MOD_NOT_FOUND);
    return NULL;
}

WINAPI BOOL GetModuleHandleExW(DWORD flags, const WCHAR* name, HMODULE* module) {
    *module = (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) ? module_for_address((uint64_t)name) : GetModuleHandleW(name);
    if (!*module) rt_set_last_error(ERROR_MOD_NOT_FOUND);
    return *module != NULL;
}

WINAPI DWORD GetModuleFileNameW(HMODULE module, WCHAR* buffer, DWORD size) {
    const WCHAR* name = (module == NULL || module == (HMODULE)rt_image_base()) ? module_path : u"kernel32.dll";
    uint32_t length = (uint32_t)rt_wcslen(name);
    if (size == 0) {
        rt_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    uint32_t copied = length < size ? length : size - 1;
    memcpy(buffer, name, copied * sizeof(WCHAR));
    buffer[copied] = 0;
    if (copied < length) {
        rt_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return size;
    }
    return copied;
}

WINAPI HMODULE LoadLibraryExW(const WCHAR* name, HANDLE file, DWORD flags) {
    (void)file;
    (void)flags;
    if (name && kernel32_wide(name)) return RUNTIME_MODULE;
    rt_set_last_error(ERROR_MOD_NOT_FOUND);
    return NULL;
}

WINAPI BOOL FreeLibrary(HMODULE module) {
    (void)module;
    return TRUE;
}

WINAPI void* GetProcAddress(HMODULE module, const char* name) {
    if (module == RUNTIME_MODULE && (uint64_t)name > 0xFFFF) {
        const win32_runtime_header_t* runtime = (const win32_runtime_header_t*)WIN32_RUNTIME_BASE;
        const win32_export_t* exports = (const win32_export_t*)runtime->exports;
        for (uint32_t i = 0; i < runtime->export_count; i++) {
            if (rt_strcmp((const char*)exports[i].name, name) == 0) return (void*)exports[i].address;
        }
    }
    rt_set_last_error(ERROR_PROC_NOT_FOUND);
    return NULL;
}

static uint32_t name_length(const WCHAR* entry) {
    uint32_t n = 0;
    while (entry[n] && (entry[n] != '=' || n == 0)) n++;
    return n;
}

static int find_variable(const WCHAR* name) {
    uint32_t length = (uint32_t)rt_wcslen(name);
    for (uint32_t i = 0; i < environment_count; i++) {
        if (name_length(environment[i]) != length) continue;
        bool same = true;
        for (uint32_t j = 0; j < length && same; j++) {
            WCHAR a = environment[i][j], b = name[j];
            if (a >= 'a' && a <= 'z') a -= 32;
            if (b >= 'a' && b <= 'z') b -= 32;
            same = a == b;
        }
        if (same) return (int)i;
    }
    return -1;
}

WINAPI WCHAR* GetEnvironmentStringsW(void) {
    uint32_t total = 1;
    for (uint32_t i = 0; i < environment_count; i++) total += (uint32_t)rt_wcslen(environment[i]) + 1;
    WCHAR* block = rt_alloc(total * sizeof(WCHAR));
    if (!block) {
        rt_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    WCHAR* at = block;
    for (uint32_t i = 0; i < environment_count; i++) {
        uint32_t n = (uint32_t)rt_wcslen(environment[i]) + 1;
        memcpy(at, environment[i], n * sizeof(WCHAR));
        at += n;
    }
    *at = 0;
    return block;
}

WINAPI BOOL FreeEnvironmentStringsW(WCHAR* block) {
    rt_free(block);
    return TRUE;
}

WINAPI BOOL SetEnvironmentVariableW(const WCHAR* name, const WCHAR* value) {
    if (!name || !name[0]) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    int index = find_variable(name);
    if (!value) {
        if (index < 0) return TRUE;
        rt_free(environment[index]);
        environment[index] = environment[--environment_count];
        return TRUE;
    }
    uint32_t n = (uint32_t)rt_wcslen(name), v = (uint32_t)rt_wcslen(value);
    WCHAR* entry = rt_alloc((n + v + 2) * sizeof(WCHAR));
    if (!entry || (index < 0 && environment_count >= MAX_ENVIRONMENT)) {
        rt_free(entry);
        rt_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    memcpy(entry, name, n * sizeof(WCHAR));
    entry[n] = '=';
    memcpy(entry + n + 1, value, (v + 1) * sizeof(WCHAR));
    if (index >= 0) rt_free(environment[index]);
    else index = (int)environment_count++;
    environment[index] = entry;
    return TRUE;
}

WINAPI DWORD GetEnvironmentVariableW(const WCHAR* name, WCHAR* buffer, DWORD size) {
    int index = find_variable(name);
    if (index < 0) {
        rt_set_last_error(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }
    const WCHAR* value = environment[index] + name_length(environment[index]) + 1;
    uint32_t length = (uint32_t)rt_wcslen(value);
    if (length + 1 > size) return length + 1;
    memcpy(buffer, value, (length + 1) * sizeof(WCHAR));
    return length;
}
#include "program.h"
#include "memory.h"
#include "string_utils.h"
#include "win32_runtime.h"

extern const uint8_t win32_runtime_start[];
extern const uint8_t win32_runtime_end[];

#define DOS_LFANEW_OFFSET 0x3C
#define PE_SIGNATURE 0x00004550u
#define MACHINE_AMD64 0x8664
#define OPTIONAL_MAGIC_PE32_PLUS 0x20B
#define FILE_RELOCS_STRIPPED 0x0001
#define SUBSYSTEM_WINDOWS_GUI 2
#define SUBSYSTEM_WINDOWS_CUI 3
#define DIRECTORY_IMPORT 1
#define DIRECTORY_BASERELOC 5
#define SECTION_WRITE 0x80000000u
#define RELOC_ABSOLUTE 0
#define RELOC_DIR64 10
#define RELOC_TYPE_SHIFT 12
#define RELOC_OFFSET_MASK 0x0FFF
#define ORDINAL_FLAG (1ULL << 63)
#define NAME_LENGTH 128
#define DLL_NAME_LENGTH 64
#define MAX_SECTIONS 96

typedef struct {
    uint32_t signature;
    uint16_t machine;
    uint16_t section_count;
    uint32_t timestamp;
    uint32_t symbol_table;
    uint32_t symbol_count;
    uint16_t optional_size;
    uint16_t characteristics;
} PACKED pe_file_header_t;

typedef struct {
    uint32_t rva;
    uint32_t size;
} PACKED pe_directory_t;

typedef struct {
    uint16_t magic;
    uint8_t linker_major, linker_minor;
    uint32_t code_size, data_size, bss_size;
    uint32_t entry;
    uint32_t code_base;
    uint64_t image_base;
    uint32_t section_alignment, file_alignment;
    uint16_t os_major, os_minor, image_major, image_minor, subsystem_major, subsystem_minor;
    uint32_t win32_version;
    uint32_t image_size;
    uint32_t headers_size;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t stack_reserve, stack_commit, heap_reserve, heap_commit;
    uint32_t loader_flags;
    uint32_t directory_count;
    pe_directory_t directories[16];
} PACKED pe_optional_header_t;

typedef struct {
    char name[8];
    uint32_t virtual_size;
    uint32_t rva;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t relocations, line_numbers;
    uint16_t relocation_count, line_number_count;
    uint32_t characteristics;
} PACKED pe_section_t;

typedef struct {
    uint32_t lookup_rva;
    uint32_t timestamp;
    uint32_t forwarder;
    uint32_t name_rva;
    uint32_t address_rva;
} PACKED pe_import_t;

typedef struct {
    const pe_file_header_t* file;
    const pe_optional_header_t* optional;
    const pe_section_t* sections;
    uint64_t base;
} pe_image_t;

static bool fail(char* error, const char* text) {
    string_copy(error, text);
    return false;
}

/* headers */

static const char* parse_headers(const uint8_t* data, uint32_t size, pe_image_t* pe) {
    if (size < DOS_LFANEW_OFFSET + sizeof(uint32_t)) return "file is too short for a PE header";
    uint32_t offset = *(const uint32_t*)(data + DOS_LFANEW_OFFSET);
    if (offset > size || size - offset < sizeof(pe_file_header_t) + sizeof(pe_optional_header_t)) return "PE header runs past the end of the file";
    pe->file = (const pe_file_header_t*)(data + offset);
    pe->optional = (const pe_optional_header_t*)(pe->file + 1);
    if (pe->file->signature != PE_SIGNATURE) return "MZ file without a PE header, 16 bit DOS programs are not supported";
    if (pe->file->machine != MACHINE_AMD64 || pe->optional->magic != OPTIONAL_MAGIC_PE32_PLUS) return "not a 64 bit PE32+ program, 32 bit Windows programs are not supported";
    if (pe->optional->subsystem == SUBSYSTEM_WINDOWS_GUI) return "Windows GUI program, Apollo provides console programs with kernel32 only";
    if (pe->optional->subsystem != SUBSYSTEM_WINDOWS_CUI) return "PE file is not a Windows console program";
    uint64_t table = offset + sizeof(pe_file_header_t) + pe->file->optional_size;
    if (pe->file->section_count > MAX_SECTIONS || table + (uint64_t)pe->file->section_count * sizeof(pe_section_t) > size) return "PE section table is malformed";
    pe->sections = (const pe_section_t*)(data + table);
    if (pe->optional->headers_size > size || pe->optional->image_size == 0) return "PE image size is malformed";
    return NULL;
}

static bool image_fits(uint64_t base, uint64_t size) {
    return address_space_is_user(base, size) && program_range_free(base, size);
}

/* mapping */

static const char* map_image(const uint8_t* data, uint32_t size, pe_image_t* pe) {
    uint64_t length = ALIGN_UP(pe->optional->image_size, PAGE_SIZE);
    pe->base = pe->optional->image_base;
    if (!image_fits(pe->base, length)) {
        if (pe->file->characteristics & FILE_RELOCS_STRIPPED) return "image base is not available and the program has no relocations";
        pe->base = 0;
    }
    pe->base = program_map(pe->base, length, PROGRAM_MAP_COMMIT | PROGRAM_MAP_WRITE, pe->base != 0);
    if (!pe->base) return "not enough memory for the program image";
    memcpy((void*)(uintptr_t)pe->base, data, pe->optional->headers_size);
    for (uint32_t i = 0; i < pe->file->section_count; i++) {
        const pe_section_t* s = &pe->sections[i];
        uint32_t raw = s->raw_size < s->virtual_size || s->virtual_size == 0 ? s->raw_size : s->virtual_size;
        if (s->raw_offset > size || raw > size - s->raw_offset) return "PE section runs past the end of the file";
        if ((uint64_t)s->rva + (s->virtual_size > raw ? s->virtual_size : raw) > length) return "PE section lies outside the image";
        memcpy((void*)(uintptr_t)(pe->base + s->rva), data + s->raw_offset, raw);
    }
    return NULL;
}

static void* at_rva(const pe_image_t* pe, uint32_t rva) {
    return (void*)(uintptr_t)(pe->base + rva);
}

static const char* apply_relocations(const pe_image_t* pe) {
    int64_t delta = (int64_t)(pe->base - pe->optional->image_base);
    const pe_directory_t* dir = &pe->optional->directories[DIRECTORY_BASERELOC];
    if (delta == 0 || dir->size == 0) return NULL;
    uint32_t done = 0;
    while (done + 2 * sizeof(uint32_t) <= dir->size) {
        const uint32_t* block = (const uint32_t*)at_rva(pe, dir->rva + done);
        uint32_t page = block[0], block_size = block[1];
        if (block_size < 2 * sizeof(uint32_t) || done + block_size > dir->size) return "PE relocation table is malformed";
        const uint16_t* entries = (const uint16_t*)(block + 2);
        for (uint32_t i = 0; i < (block_size - 2 * sizeof(uint32_t)) / sizeof(uint16_t); i++) {
            uint16_t type = entries[i] >> RELOC_TYPE_SHIFT;
            if (type == RELOC_ABSOLUTE) continue;
            if (type != RELOC_DIR64) return "PE relocation type is not supported";
            *(uint64_t*)at_rva(pe, page + (entries[i] & RELOC_OFFSET_MASK)) += (uint64_t)delta;
        }
        done += block_size;
    }
    return NULL;
}

/* imports */

static bool same_name_ignoring_case(const char* a, const char* b) {
    for (; *a && *b; a++, b++) {
        char x = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char y = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (x != y) return false;
    }
    return *a == *b;
}

// kernel32 and the api-ms-win-core sets that forward to it are served by the runtime
static bool runtime_serves(const char* dll) {
    const char prefix[] = "api-ms-win-core-";
    char head[sizeof(prefix)];
    string_copy_n(head, dll, sizeof(head));
    return same_name_ignoring_case(dll, "kernel32.dll") || same_name_ignoring_case(head, prefix);
}

static const win32_runtime_header_t* runtime_header(void) {
    return (const win32_runtime_header_t*)win32_runtime_start;
}

static const char* runtime_text(uint64_t address) {
    return (const char*)(win32_runtime_start + (address - WIN32_RUNTIME_BASE));
}

static uint64_t runtime_export(const char* name) {
    const win32_export_t* exports = (const win32_export_t*)runtime_text(runtime_header()->exports);
    for (uint32_t i = 0; i < runtime_header()->export_count; i++) {
        if (string_equals(runtime_text(exports[i].name), name)) return exports[i].address;
    }
    return 0;
}

static void missing_import(char* error, const char* dll, const char* name) {
    string_copy(error, "missing import ");
    string_concat_n(error, dll, PROGRAM_ERROR_LENGTH);
    string_concat_n(error, "!", PROGRAM_ERROR_LENGTH);
    string_concat_n(error, name, PROGRAM_ERROR_LENGTH);
}

static bool bind_module(const pe_image_t* pe, const pe_import_t* import, char* error) {
    char dll[DLL_NAME_LENGTH];
    string_copy_n(dll, (const char*)at_rva(pe, import->name_rva), sizeof(dll));
    if (!runtime_serves(dll)) {
        string_copy(error, "needs ");
        string_concat_n(error, dll, PROGRAM_ERROR_LENGTH);
        string_concat_n(error, ", Apollo provides kernel32.dll only (build with a static C runtime)", PROGRAM_ERROR_LENGTH);
        return false;
    }
    const uint64_t* lookup = (const uint64_t*)at_rva(pe, import->lookup_rva ? import->lookup_rva : import->address_rva);
    uint64_t* slots = (uint64_t*)at_rva(pe, import->address_rva);
    for (uint32_t i = 0; lookup[i]; i++) {
        if (lookup[i] & ORDINAL_FLAG) return fail(error, "imports by ordinal are not supported");
        const char* name = (const char*)at_rva(pe, (uint32_t)lookup[i] + sizeof(uint16_t));
        uint64_t address = runtime_export(name);
        if (!address) {
            char shown[NAME_LENGTH];
            string_copy_n(shown, name, sizeof(shown));
            missing_import(error, dll, shown);
            return false;
        }
        slots[i] = address;
    }
    return true;
}

static bool bind_imports(const pe_image_t* pe, char* error) {
    const pe_directory_t* dir = &pe->optional->directories[DIRECTORY_IMPORT];
    if (dir->size == 0) return true;
    for (const pe_import_t* import = (const pe_import_t*)at_rva(pe, dir->rva); import->name_rva; import++) {
        if (!bind_module(pe, import, error)) return false;
    }
    return true;
}

static void protect_sections(const pe_image_t* pe) {
    address_space_protect(&program.as, pe->base, pe->optional->headers_size, false);
    for (uint32_t i = 0; i < pe->file->section_count; i++) {
        const pe_section_t* s = &pe->sections[i];
        if (!(s->characteristics & SECTION_WRITE)) address_space_protect(&program.as, pe->base + s->rva, s->virtual_size, false);
    }
}

/* runtime */

// Mapped before the image so an image base on top of it is seen as taken
static bool map_runtime(void) {
    const win32_runtime_header_t* header = runtime_header();
    uint64_t blob = (uint64_t)(win32_runtime_end - win32_runtime_start);
    uint64_t length = ALIGN_UP(header->end - WIN32_RUNTIME_BASE, PAGE_SIZE);
    if (header->magic != WIN32_RUNTIME_MAGIC || blob > length) return false;
    if (!program_map(WIN32_RUNTIME_BASE, length, PROGRAM_MAP_COMMIT | PROGRAM_MAP_WRITE, true)) return false;
    memcpy((void*)(uintptr_t)WIN32_RUNTIME_BASE, win32_runtime_start, blob);
    return true;
}

bool pe_load(const uint8_t* data, uint32_t size, interrupt_frame_t* frame, char* error) {
    pe_image_t pe;
    if (!map_runtime()) return fail(error, "not enough memory for the Win32 runtime");
    const char* problem = parse_headers(data, size, &pe);
    if (!problem) problem = map_image(data, size, &pe);
    if (!problem) problem = apply_relocations(&pe);
    if (problem) return fail(error, problem);
    if (!bind_imports(&pe, error)) return false;
    protect_sections(&pe);
    ((win32_runtime_header_t*)(uintptr_t)WIN32_RUNTIME_BASE)->image_base = pe.base;
    program.image_base = pe.base;
    program.image_end = pe.base + ALIGN_UP(pe.optional->image_size, PAGE_SIZE);
    program.brk_start = program.brk_end = program.image_end;
    program.entry = pe.base + pe.optional->entry;
    frame->rip = runtime_header()->entry;
    frame->rsp = linux_build_stack(0, 0, 0);
    if (!frame->rsp) return fail(error, "the arguments do not fit on the stack");
    return true;
}
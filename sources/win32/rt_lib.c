#include "runtime.h"

#define STDERR_FD 2
#define HEX_DIGITS "0123456789ABCDEF"
#define NS_PER_SECOND 1000000000ULL
#define CLOCK_REALTIME 0
#define SURROGATE_HIGH_FIRST 0xD800
#define SURROGATE_LOW_FIRST 0xDC00
#define SURROGATE_LAST 0xDFFF
#define SURROGATE_BASE 0x10000
#define REPLACEMENT_CHARACTER 0xFFFD
#define UNICODE_LAST 0x10FFFF
#define LINUX_EPERM 1
#define LINUX_EBADF 9
#define LINUX_ENOMEM 12
#define LINUX_EACCES 13
#define LINUX_ENOTDIR 20
#define LINUX_EISDIR 21
#define LINUX_EINVAL 22
#define LINUX_EMFILE 24
#define LINUX_ENOSPC 28
#define LINUX_ENAMETOOLONG 36
#define LINUX_ENOTEMPTY 39

void* memset(void* dest, int value, size_t size) {
    uint8_t* d = dest;
    for (size_t i = 0; i < size; i++) d[i] = (uint8_t)value;
    return dest;
}

void* memcpy(void* dest, const void* src, size_t size) {
    uint8_t* d = dest;
    const uint8_t* s = src;
    for (size_t i = 0; i < size; i++) d[i] = s[i];
    return dest;
}

void* memmove(void* dest, const void* src, size_t size) {
    uint8_t* d = dest;
    const uint8_t* s = src;
    if (d < s) for (size_t i = 0; i < size; i++) d[i] = s[i];
    else for (size_t i = size; i > 0; i--) d[i - 1] = s[i - 1];
    return dest;
}

int memcmp(const void* a, const void* b, size_t size) {
    const uint8_t* x = a;
    const uint8_t* y = b;
    for (size_t i = 0; i < size; i++) if (x[i] != y[i]) return x[i] - y[i];
    return 0;
}

size_t rt_strlen(const char* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

size_t rt_wcslen(const WCHAR* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int rt_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (uint8_t)*a - (uint8_t)*b;
}

static char lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

bool rt_names_equal(const char* a, const char* b) {
    while (*a && lower(*a) == lower(*b)) { a++; b++; }
    return *a == *b;
}

bool rt_wide_names_equal(const WCHAR* a, const char* b) {
    while (*a && *a < 0x80 && lower((char)*a) == lower(*b)) { a++; b++; }
    return *a == 0 && *b == 0;
}

static uint32_t decode_utf8(const uint8_t* in, uint32_t length, uint32_t* used, bool* invalid) {
    uint8_t c = in[0];
    uint32_t extra = c < 0x80 ? 0 : (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : 4;
    uint32_t point = extra == 0 ? c : extra == 1 ? (c & 0x1Fu) : extra == 2 ? (c & 0x0Fu) : (c & 0x07u);
    *used = 1;
    if (extra == 4 || extra >= length) { *invalid = true; return REPLACEMENT_CHARACTER; }
    for (uint32_t i = 1; i <= extra; i++) {
        if ((in[i] & 0xC0) != 0x80) { *invalid = true; return REPLACEMENT_CHARACTER; }
        point = (point << 6) | (in[i] & 0x3Fu);
    }
    *used = extra + 1;
    static const uint32_t minimum[] = {0, 0x80, 0x800, 0x10000};
    bool bad = point < minimum[extra] || point > UNICODE_LAST || (point >= SURROGATE_HIGH_FIRST && point <= SURROGATE_LAST);
    if (bad) { *invalid = true; return REPLACEMENT_CHARACTER; }
    return point;
}

uint32_t rt_utf8_to_utf16(const char* in, uint32_t in_length, WCHAR* out, uint32_t out_size, bool* invalid) {
    uint32_t written = 0;
    const uint8_t* p = (const uint8_t*)in;
    for (uint32_t i = 0; i < in_length;) {
        uint32_t used;
        uint32_t point = decode_utf8(p + i, in_length - i, &used, invalid);
        i += used;
        if (point >= SURROGATE_BASE) {
            point -= SURROGATE_BASE;
            if (out && written + 1 < out_size) {
                out[written] = (WCHAR)(SURROGATE_HIGH_FIRST + (point >> 10));
                out[written + 1] = (WCHAR)(SURROGATE_LOW_FIRST + (point & 0x3FF));
            }
            written += 2;
        } else {
            if (out && written < out_size) out[written] = (WCHAR)point;
            written++;
        }
    }
    return written;
}

static uint32_t encode_utf8(uint32_t point, char* out) {
    if (point < 0x80) { out[0] = (char)point; return 1; }
    if (point < 0x800) { out[0] = (char)(0xC0 | (point >> 6)); out[1] = (char)(0x80 | (point & 0x3F)); return 2; }
    if (point < 0x10000) {
        out[0] = (char)(0xE0 | (point >> 12));
        out[1] = (char)(0x80 | ((point >> 6) & 0x3F));
        out[2] = (char)(0x80 | (point & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (point >> 18));
    out[1] = (char)(0x80 | ((point >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((point >> 6) & 0x3F));
    out[3] = (char)(0x80 | (point & 0x3F));
    return 4;
}

uint32_t rt_utf16_to_utf8(const WCHAR* in, uint32_t in_length, char* out, uint32_t out_size, bool* invalid) {
    uint32_t written = 0;
    for (uint32_t i = 0; i < in_length; i++) {
        uint32_t point = in[i];
        bool high = point >= SURROGATE_HIGH_FIRST && point < SURROGATE_LOW_FIRST;
        bool low = point >= SURROGATE_LOW_FIRST && point <= SURROGATE_LAST;
        if (high && i + 1 < in_length && in[i + 1] >= SURROGATE_LOW_FIRST && in[i + 1] <= SURROGATE_LAST) {
            point = SURROGATE_BASE + ((point - SURROGATE_HIGH_FIRST) << 10) + (in[i + 1] - SURROGATE_LOW_FIRST);
            i++;
        } else if (high || low) {
            *invalid = true;
            point = REPLACEMENT_CHARACTER;
        }
        char bytes[4];
        uint32_t n = encode_utf8(point, bytes);
        if (out && written + n <= out_size) memcpy(out + written, bytes, n);
        written += n;
    }
    return written;
}

bool rt_path_from_wide(const WCHAR* wide, char* out, uint32_t size) {
    bool invalid = false;
    uint32_t length = (uint32_t)rt_wcslen(wide);
    if (length >= 2 && wide[1] == ':' && ((wide[0] | 0x20) >= 'a' && (wide[0] | 0x20) <= 'z')) {
        wide += 2;
        length -= 2;
    }
    uint32_t n = rt_utf16_to_utf8(wide, length, out, size - 1, &invalid);
    if (n >= size) return false;
    out[n] = '\0';
    for (uint32_t i = 0; i < n; i++) if (out[i] == '\\') out[i] = '/';
    if (n == 0) { out[0] = '/'; out[1] = '\0'; }
    return true;
}

void rt_write_text(const char* text) {
    sys3(LINUX_WRITE, STDERR_FD, text, rt_strlen(text));
}

void rt_write_hex(uint64_t value, int digits) {
    char text[17];
    for (int i = digits - 1; i >= 0; i--) {
        text[i] = HEX_DIGITS[value & 0xF];
        value >>= 4;
    }
    text[digits] = '\0';
    rt_write_text(text);
}

DWORD rt_error_from_errno(int64_t error) {
    switch (-error) {
        case LINUX_ENOENT: return ERROR_FILE_NOT_FOUND;
        case LINUX_ENOTDIR: return ERROR_PATH_NOT_FOUND;
        case LINUX_EPERM: case LINUX_EACCES: case LINUX_EISDIR: return ERROR_ACCESS_DENIED;
        case LINUX_EBADF: return ERROR_INVALID_HANDLE;
        case LINUX_ENOMEM: return ERROR_NOT_ENOUGH_MEMORY;
        case LINUX_EEXIST: return ERROR_FILE_EXISTS;
        case LINUX_EMFILE: return ERROR_TOO_MANY_OPEN_FILES;
        case LINUX_ENOSPC: return ERROR_NOT_ENOUGH_MEMORY;
        case LINUX_ENAMETOOLONG: return ERROR_INVALID_PARAMETER;
        case LINUX_ENOTEMPTY: return ERROR_DIR_NOT_EMPTY;
        case LINUX_EINVAL: return ERROR_INVALID_PARAMETER;
        default: return ERROR_INVALID_FUNCTION;
    }
}

void rt_set_error_from(int64_t result) {
    rt_set_last_error(rt_error_from_errno(result));
}

uint64_t rt_now_ns(void) {
    linux_timespec_t ts;
    sys2(LINUX_CLOCK_GETTIME, CLOCK_REALTIME, &ts);
    return (uint64_t)ts.seconds * NS_PER_SECOND + (uint64_t)ts.nanoseconds;
}

void rt_exit(DWORD code) {
    for (;;) sys1(APOLLO_EXIT_STATUS, code);
}
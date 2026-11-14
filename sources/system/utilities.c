#include "time_keeper.h"
#include "string_utils.h"
#include "types.h"

#define ASCII_CASE_OFFSET ('a' - 'A')

uint32_t get_system_time(void) {
    return (uint32_t)time_keeper_get_uptime_ms();
}

uint32_t string_length(const char* str) {
    uint32_t len = 0;
    while (str && str[len] != '\0') len++;
    return len;
}

void string_copy(char* dest, const char* src) {
    if (!dest || !src) return;
    while (*src) {
        *dest++ = *src++;
    }
    *dest = '\0';
}

// Copies at most n characters and always terminates, unlike strncpy
void string_copy_n(char* dest, const char* src, uint32_t n) {
    if (!dest || !src || n == 0) return;
    uint32_t i = 0;
    while (i + 1 < n && src[i]) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

void string_concat(char* dest, const char* src) {
    if (!dest || !src) return;
    string_copy(dest + string_length(dest), src);
}

// n is the total size of dest including the terminator
void string_concat_n(char* dest, const char* src, uint32_t n) {
    if (!dest || !src) return;
    uint32_t used = string_length(dest);
    if (used >= n) return;
    string_copy_n(dest + used, src, n - used);
}

int string_compare(const char* str1, const char* str2) {
    if (!str1 || !str2) return (str1 == str2) ? 0 : (str1 ? 1 : -1);
    while (*str1 && *str1 == *str2) {
        str1++;
        str2++;
    }
    return (int)(unsigned char)*str1 - (int)(unsigned char)*str2;
}

bool string_equals(const char* str1, const char* str2) {
    return string_compare(str1, str2) == 0;
}

bool string_contains(const char* str, char c) {
    return string_find_char(str, c) != NULL;
}

char* string_find_char(const char* str, char c) {
    if (!str) return NULL;
    for (; *str; str++) {
        if (*str == c) return (char*)str;
    }
    return NULL;
}

void string_to_upper(char* str) {
    for (; str && *str; str++) {
        if (*str >= 'a' && *str <= 'z') *str -= ASCII_CASE_OFFSET;
    }
}

void string_to_lower(char* str) {
    for (; str && *str; str++) {
        if (*str >= 'A' && *str <= 'Z') *str += ASCII_CASE_OFFSET;
    }
}

static bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

void string_trim(char* str) {
    if (!str) return;
    uint32_t start = 0;
    while (is_space(str[start])) start++;
    uint32_t end = string_length(str);
    while (end > start && is_space(str[end - 1])) end--;
    uint32_t i = 0;
    for (uint32_t j = start; j < end; j++) str[i++] = str[j];
    str[i] = '\0';
}

void* memset(void* dest, int value, size_t size) {
    uint8_t* d = (uint8_t*)dest;
    uint8_t val = (uint8_t)value;
    for (size_t i = 0; i < size; i++) {
        d[i] = val;
    }
    return dest;
}

// The compiler emits calls to this for struct copies
void* memcpy(void* dest, const void* src, size_t size) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (size_t i = 0; i < size; i++) {
        d[i] = s[i];
    }
    return dest;
}
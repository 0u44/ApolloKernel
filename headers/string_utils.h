#ifndef APOLLO_STRING_UTILS_H
#define APOLLO_STRING_UTILS_H

#include "types.h"

// Basic string operations
uint32_t string_length(const char* str);
void string_copy(char* dest, const char* src);
void string_copy_n(char* dest, const char* src, uint32_t n);
void string_concat(char* dest, const char* src);
void string_concat_n(char* dest, const char* src, uint32_t n);

// String comparison
int string_compare(const char* str1, const char* str2);
bool string_equals(const char* str1, const char* str2);

// String searching
bool string_contains(const char* str, char c);
char* string_find_char(const char* str, char c);

// String manipulation
void string_to_upper(char* str);
void string_to_lower(char* str);
void string_trim(char* str);

#endif
#ifndef APOLLO_ACC_COMPILER_H
#define APOLLO_ACC_COMPILER_H

#include "types.h"

#define ACC_MAX_TOKENS 4096
#define ACC_MAX_CODE_SIZE 16384
#define ACC_MAX_DATA_SIZE 8192
#define ACC_TOKEN_TEXT 160

typedef enum {
    COMPILE_SUCCESS = 0,
    COMPILE_ERROR_SYNTAX = 1,
    COMPILE_ERROR_FILE = 2,
    COMPILE_ERROR_MEMORY = 3
} compile_result_t;

void acc_initialize(void);

compile_result_t acc_compile_file(const char* source_file, const char* output_file);
compile_result_t acc_compile_file_native(const char* source_file, const char* output_file);

compile_result_t acc_compile_string(const char* source_code, uint8_t* output_buffer, uint32_t* output_size);

const char* acc_get_error_message(void);

void acc_print_version(void);

#endif
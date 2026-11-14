#ifndef APOLLO_EXECUTOR_H
#define APOLLO_EXECUTOR_H

#include "types.h"
#include "filesystem.h"

typedef enum {
    EXEC_SUCCESS = 0,
    EXEC_ERROR_FILE_NOT_FOUND = 1,
    EXEC_ERROR_INVALID_FILE = 2,
    EXEC_ERROR_RUNTIME_ERROR = 3
} exec_result_t;

void executor_initialize(void);
exec_result_t executor_load_file(const char* filename);
exec_result_t executor_run(void);
exec_result_t executor_execute_file(const char* filename);
void executor_show_bytecode(const char* filename);
int32_t executor_get_exit_code(void);
const char* executor_get_error_message(void);
bool executor_write_native(const char* path, const char* program_name);

#endif
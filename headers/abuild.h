#ifndef APOLLO_ABUILD_H
#define APOLLO_ABUILD_H

#include "types.h"

#define ABUILD_MAX_TARGETS 32
#define ABUILD_MAX_DEPENDENCIES 16
#define ABUILD_MAX_COMMANDS 8
#define ABUILD_MAX_VARIABLES 64
#define ABUILD_LINE_LENGTH 256

typedef struct {
    char name[64];
    char dependencies[ABUILD_MAX_DEPENDENCIES][64];
    uint32_t dependency_count;
    char commands[ABUILD_MAX_COMMANDS][ABUILD_LINE_LENGTH];
    uint32_t command_count;
} build_target_t;

typedef struct {
    char name[64];
    char value[256];
} build_variable_t;

typedef struct {
    build_target_t targets[ABUILD_MAX_TARGETS];
    uint32_t target_count;
    
    build_variable_t variables[ABUILD_MAX_VARIABLES];
    uint32_t variable_count;
    
    char default_target[64];
    
    char error_message[256];
    bool has_error;
} buildfile_t;

typedef enum {
    BUILD_SUCCESS = 0,
    BUILD_ERROR_FILE_NOT_FOUND = 1,
    BUILD_ERROR_PARSE = 2,
    BUILD_ERROR_TARGET_NOT_FOUND = 3,
    BUILD_ERROR_COMMAND_FAILED = 4
} build_result_t;

void abuild_initialize(void);

build_result_t abuild_load_buildfile(const char* filename, buildfile_t* buildfile);

build_result_t abuild_execute_target(buildfile_t* buildfile, const char* target_name);

build_result_t abuild_build_all(buildfile_t* buildfile);

build_result_t abuild_clean(buildfile_t* buildfile);

const char* abuild_get_error_message(buildfile_t* buildfile);

void abuild_print_targets(buildfile_t* buildfile);

#endif
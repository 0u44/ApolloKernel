#ifndef APOLLO_ACC_RUNTIME_H
#define APOLLO_ACC_RUNTIME_H

#include "types.h"

// Native acc programs load here, the runtime first and the translated code after it
#define ACC_RUNTIME_BASE 0x400000ULL
#define ACC_RUNTIME_MAGIC 0x54524341u

#define ACC_TRAP_INDEX 1
#define ACC_TRAP_DIVIDE 2

// Sits at the first byte of the runtime, the translator fills the last three fields
typedef struct {
    uint32_t magic;
    uint32_t reserved;
    uint64_t entry;
    uint64_t sys;
    uint64_t trap;
    uint64_t end;
    uint64_t program;
    uint64_t data;
    uint64_t data_size;
} acc_runtime_header_t;

#endif
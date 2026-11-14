#ifndef APOLLO_WIN32_RUNTIME_H
#define APOLLO_WIN32_RUNTIME_H

#include "types.h"

// The runtime is linked to run here, inside every PE program's address space
#define WIN32_RUNTIME_BASE 0x00007FF000000000ULL
#define WIN32_RUNTIME_MAGIC 0x32335741u

typedef struct {
    uint64_t name;
    uint64_t address;
} win32_export_t;

// Sits at the first byte of the runtime, the loader reads the exports and fills image_base
typedef struct {
    uint32_t magic;
    uint32_t export_count;
    uint64_t exports;
    uint64_t entry;
    uint64_t end;
    uint64_t image_base;
} win32_runtime_header_t;

#endif
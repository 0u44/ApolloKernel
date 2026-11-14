#ifndef APOLLO_MEMORY_H
#define APOLLO_MEMORY_H

#include "types.h"

#define PAGE_SIZE 4096
#define BOOT_MODULE_NAME_LENGTH 64
#define BOOT_MODULES_MAX 16

#define USER_WINDOW_START 0x400000ULL

void memory_initialize(void);

uint64_t frame_alloc(void);
uint64_t frame_alloc_contiguous(uint32_t count);
void frame_free(uint64_t address);
void frame_free_contiguous(uint64_t address, uint32_t count);
uint32_t memory_free_frames(void);
uint32_t memory_total_frames(void);
uint64_t memory_user_window_end(void);

uint32_t boot_module_count(void);
bool boot_module_get(uint32_t index, uint8_t** data, uint32_t* size, const char** name);

#endif
#ifndef APOLLO_ADDRESS_SPACE_H
#define APOLLO_ADDRESS_SPACE_H

#include "types.h"

#define USER_HIGH_START 0x100000000ULL
#define USER_HIGH_END 0x0000800000000000ULL

typedef struct {
    uint64_t p4;
    uint64_t window_p2;
    uint32_t pages;
} address_space_t;

bool address_space_create(address_space_t* as);
void address_space_destroy(address_space_t* as);
void address_space_activate(const address_space_t* as);

bool address_space_is_user(uint64_t address, uint64_t length);
bool address_space_map(address_space_t* as, uint64_t address, uint64_t length, bool writable);
void address_space_unmap(address_space_t* as, uint64_t address, uint64_t length);
void address_space_protect(address_space_t* as, uint64_t address, uint64_t length, bool writable);
bool address_space_is_mapped(const address_space_t* as, uint64_t address, bool write);
bool address_space_range_mapped(const address_space_t* as, uint64_t address, uint64_t length, bool write);

#endif
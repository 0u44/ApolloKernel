#ifndef APOLLO_ACC_NATIVE_H
#define APOLLO_ACC_NATIVE_H

#include "types.h"

#define ACC_NATIVE_ERROR_LENGTH 128

bool acc_native_write(const uint8_t* image, uint32_t size, const char* output, char* error);

#endif
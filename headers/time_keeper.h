#ifndef APOLLO_TIME_KEEPER_H
#define APOLLO_TIME_KEEPER_H

#include "types.h"

void time_keeper_initialize(void);

void time_keeper_get_datetime(int* year, int* month, int* day, int* hour, int* minute, int* second);

uint64_t time_keeper_get_uptime_seconds(void);
uint64_t time_keeper_get_uptime_ms(void);
uint64_t time_keeper_get_uptime_ns(void);
uint64_t time_keeper_get_tsc_per_ms(void);
uint64_t time_keeper_get_unix_time(void);
void time_keeper_delay_ms(uint32_t milliseconds);
void time_keeper_delay_us(uint32_t microseconds);

uint32_t get_system_time(void);

#endif
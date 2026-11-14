#ifndef APOLLO_PROCESS_MANAGER_H
#define APOLLO_PROCESS_MANAGER_H

#include "types.h"

#define TASK_KERNEL 0

typedef enum {
    PROCESS_STATE_RUNNING = 0,
    PROCESS_STATE_READY = 1,
    PROCESS_STATE_BLOCKED = 2,
    PROCESS_STATE_TERMINATED = 3
} process_state_t;

typedef enum {
    PROCESS_TYPE_KERNEL = 0,
    PROCESS_TYPE_SYSTEM = 1,
    PROCESS_TYPE_USER = 2
} process_type_t;

typedef struct {
    uint32_t pid;
    char name[64];
    process_state_t state;
    process_type_t type;
    uint32_t cpu_time;      // Milliseconds measured with the TSC
    uint32_t memory_usage;  // Bytes, 0 when the task has no memory of its own
    uint32_t parent_pid;
    uint32_t start_time;
    void* entry_point;
    bool is_active;
} process_t;

typedef struct {
    uint32_t total_processes;
    uint32_t running_processes;
    uint32_t blocked_processes;
    uint32_t total_cpu_time;
    uint32_t context_switches;
} process_stats_t;

void process_manager_initialize(void);

uint32_t process_create(const char* name, process_type_t type, void* entry_point);
bool process_terminate(uint32_t pid);
bool process_suspend(uint32_t pid);
bool process_resume(uint32_t pid);
bool process_is_runnable(uint32_t pid);

bool process_get_info(uint32_t pid, process_t* info);
uint32_t process_list(process_t* processes, uint32_t max_count);
bool process_get_stats(process_stats_t* stats);

uint32_t process_get_current_pid(void);
void process_account_begin(uint32_t pid);
void process_account_end(void);

const char* process_get_state_string(process_state_t state);
const char* process_get_type_string(process_type_t type);

#endif
#include "process_manager.h"
#include "heap_allocator.h"
#include "time_keeper.h"
#include "string_utils.h"
#include "types.h"

#define MAX_PROCESSES 64
#define US_PER_MS 1000

extern uint8_t __kernel_start[];
extern uint8_t __kernel_end[];

typedef struct {
    process_t processes[MAX_PROCESSES];
    uint64_t cpu_us[MAX_PROCESSES];
    uint32_t next_pid;
    uint32_t current_pid;
    uint32_t accounting_slot;
    uint64_t accounting_start_tsc;
    bool accounting;
    uint32_t total_context_switches;
    bool is_initialized;
} process_manager_state_t;

static process_manager_state_t pm_state = {0};

static inline uint64_t read_tsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static uint32_t find_free_process_slot(void) {
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        if (!pm_state.processes[i].is_active) {
            return i;
        }
    }
    return MAX_PROCESSES;
}

static int32_t find_slot_by_pid(uint32_t pid) {
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        if (pm_state.processes[i].is_active && pm_state.processes[i].pid == pid) {
            return (int32_t)i;
        }
    }
    return -1;
}

static process_t* find_process_by_pid(uint32_t pid) {
    int32_t slot = find_slot_by_pid(pid);
    return slot < 0 ? NULL : &pm_state.processes[slot];
}

static void add_slot(uint32_t slot, uint32_t pid, const char* name, process_type_t type, void* entry_point) {
    process_t* proc = &pm_state.processes[slot];
    proc->pid = pid;
    string_copy(proc->name, name);
    proc->state = PROCESS_STATE_READY;
    proc->type = type;
    proc->cpu_time = 0;
    proc->memory_usage = 0;
    proc->parent_pid = pm_state.current_pid;
    proc->start_time = get_system_time();
    proc->entry_point = entry_point;
    proc->is_active = true;
    pm_state.cpu_us[slot] = 0;
}

void process_manager_initialize(void) {
    if (pm_state.is_initialized) return;
    pm_state.next_pid = 1;
    pm_state.current_pid = TASK_KERNEL;
    pm_state.is_initialized = true;
    add_slot(0, TASK_KERNEL, "kernel", PROCESS_TYPE_KERNEL, NULL);
    pm_state.processes[0].state = PROCESS_STATE_RUNNING;
}

uint32_t process_create(const char* name, process_type_t type, void* entry_point) {
    if (!name || string_length(name) == 0) return 0;
    uint32_t slot = find_free_process_slot();
    if (slot >= MAX_PROCESSES) return 0;
    uint32_t pid = pm_state.next_pid++;
    add_slot(slot, pid, name, type, entry_point);
    return pid;
}

// Kernel and system tasks are part of the main loop and cannot be removed
bool process_terminate(uint32_t pid) {
    process_t* proc = find_process_by_pid(pid);
    if (!proc || proc->type != PROCESS_TYPE_USER) return false;
    proc->state = PROCESS_STATE_TERMINATED;
    proc->is_active = false;
    return true;
}

bool process_suspend(uint32_t pid) {
    process_t* proc = find_process_by_pid(pid);
    if (!proc || pid == TASK_KERNEL || proc->state == PROCESS_STATE_BLOCKED) return false;
    proc->state = PROCESS_STATE_BLOCKED;
    return true;
}

bool process_resume(uint32_t pid) {
    process_t* proc = find_process_by_pid(pid);
    if (!proc || proc->state != PROCESS_STATE_BLOCKED) return false;
    proc->state = PROCESS_STATE_READY;
    return true;
}

bool process_is_runnable(uint32_t pid) {
    process_t* proc = find_process_by_pid(pid);
    return proc && proc->state != PROCESS_STATE_BLOCKED;
}

void process_account_begin(uint32_t pid) {
    int32_t slot = find_slot_by_pid(pid);
    if (slot < 0 || pm_state.accounting) return;
    if (pid != pm_state.current_pid) pm_state.total_context_switches++;
    pm_state.current_pid = pid;
    pm_state.accounting_slot = (uint32_t)slot;
    pm_state.accounting = true;
    pm_state.processes[slot].state = PROCESS_STATE_RUNNING;
    pm_state.accounting_start_tsc = read_tsc();
}

void process_account_end(void) {
    if (!pm_state.accounting) return;
    uint64_t tsc_per_ms = time_keeper_get_tsc_per_ms();
    uint32_t slot = pm_state.accounting_slot;
    if (tsc_per_ms > 0) {
        pm_state.cpu_us[slot] += (read_tsc() - pm_state.accounting_start_tsc) * US_PER_MS / tsc_per_ms;
    }
    process_t* proc = &pm_state.processes[slot];
    if (proc->state == PROCESS_STATE_RUNNING) proc->state = PROCESS_STATE_READY;
    pm_state.accounting = false;
    pm_state.current_pid = TASK_KERNEL;
}

// Kernel time is whatever part of uptime no task has been charged for
static void refresh_derived_fields(void) {
    uint64_t tasks_us = 0;
    for (uint32_t i = 1; i < MAX_PROCESSES; i++) {
        if (!pm_state.processes[i].is_active) continue;
        pm_state.processes[i].cpu_time = (uint32_t)(pm_state.cpu_us[i] / US_PER_MS);
        tasks_us += pm_state.cpu_us[i];
    }
    uint64_t uptime_us = time_keeper_get_uptime_ms() * US_PER_MS;
    process_t* kernel = &pm_state.processes[0];
    kernel->cpu_time = (uint32_t)((uptime_us > tasks_us ? uptime_us - tasks_us : 0) / US_PER_MS);
    kernel->memory_usage = (uint32_t)(__kernel_end - __kernel_start);
}

bool process_get_info(uint32_t pid, process_t* info) {
    if (!info) return false;
    refresh_derived_fields();
    process_t* proc = find_process_by_pid(pid);
    if (!proc) return false;
    *info = *proc;
    return true;
}

uint32_t process_list(process_t* processes, uint32_t max_count) {
    if (!processes || max_count == 0) return 0;
    refresh_derived_fields();
    uint32_t count = 0;
    for (uint32_t i = 0; i < MAX_PROCESSES && count < max_count; i++) {
        if (pm_state.processes[i].is_active) {
            processes[count++] = pm_state.processes[i];
        }
    }
    return count;
}

bool process_get_stats(process_stats_t* stats) {
    if (!stats) return false;
    refresh_derived_fields();
    stats->total_processes = 0;
    stats->running_processes = 0;
    stats->blocked_processes = 0;
    stats->total_cpu_time = 0;
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        const process_t* proc = &pm_state.processes[i];
        if (!proc->is_active) continue;
        stats->total_processes++;
        stats->total_cpu_time += proc->cpu_time;
        if (proc->state == PROCESS_STATE_BLOCKED) {
            stats->blocked_processes++;
        } else {
            stats->running_processes++;
        }
    }
    stats->context_switches = pm_state.total_context_switches;
    return true;
}

uint32_t process_get_current_pid(void) {
    return pm_state.current_pid;
}

const char* process_get_state_string(process_state_t state) {
    switch (state) {
        case PROCESS_STATE_RUNNING: return "running";
        case PROCESS_STATE_READY: return "ready";
        case PROCESS_STATE_BLOCKED: return "blocked";
        case PROCESS_STATE_TERMINATED: return "terminated";
    }
    return "unknown";
}

const char* process_get_type_string(process_type_t type) {
    switch (type) {
        case PROCESS_TYPE_KERNEL: return "kernel";
        case PROCESS_TYPE_SYSTEM: return "system";
        case PROCESS_TYPE_USER: return "user";
    }
    return "unknown";
}

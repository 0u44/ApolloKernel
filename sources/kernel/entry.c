#include "types.h"
#include "terminal.h"
#include "input_manager.h"
#include "command_processor.h"
#include "heap_allocator.h"
#include "time_keeper.h"
#include "filesystem.h"
#include "process_manager.h"
#include "text_editor.h"
#include "network_manager.h"
#include "rtl8139_driver.h"
#include "audio_subsystem.h"
#include "wave_player.h"
#include "firewall.h"
#include "rate_limiter.h"
#include "secure_boot.h"
#include "security_audit.h"
#include "memory.h"
#include "cpu.h"
#include "program.h"

#define APOLLO_VERSION "1.1.2"
#define APOLLO_ARCH "x86_64"
#define APOLLO_BUILD_DATE __DATE__
#define APOLLO_BUILD_TIME __TIME__

static struct {
    uint32_t boot_time;
    uint32_t initialization_steps;
    bool all_systems_ready;
} system_state = {0};

static void apollo_display_startup_sequence(void);
static void apollo_system_update_audio(void);
static void apollo_initialize_all_systems(void);
static void cpu_relax(void);
static void update_system_activity(void);
static void create_kernel_tasks(void);

static void apollo_display_startup_sequence(void) {
    terminal_initialize();

    terminal_set_custom_color(1, 255, 165, 0);   // Orange
    terminal_set_custom_color(2, 255, 215, 0);   // Gold
    terminal_set_custom_color(3, 255, 69, 0);    // Red-Orange
    terminal_set_custom_color(4, 255, 140, 0);   // Dark Orange
    terminal_set_custom_color(5, 255, 20, 147);  // Deep Pink
    terminal_set_custom_color(6, 138, 43, 226);  // Blue Violet
    terminal_set_custom_color(7, 255, 255, 255); // White

    terminal_clear();

    terminal_set_color(14, 0);
    terminal_write_string("          \\   |   /\n");
    terminal_set_color(3, 0);
    terminal_write_string("       --  .----.  --\n");
    terminal_set_color(14, 0);
    terminal_write_string("          /      \\\n");
    terminal_write_string("         | APOLLO |\n");
    terminal_write_string("          \\      /\n");
    terminal_set_color(3, 0);
    terminal_write_string("       --  '----'  --\n");
    terminal_set_color(14, 0);
    terminal_write_string("          /   |   \\\n\n");
    terminal_set_color(3, 0);
    terminal_write_string("Welcome to\n");
    terminal_set_color(14, 0);
    terminal_write_string("Apollo Operating System\n");
    terminal_set_color(7, 0);

    terminal_write_string("\nApollo Kernel v");
    terminal_write_string(APOLLO_VERSION);
    terminal_write_string(" - x86_64 Operating System\n");
    terminal_write_string("Build: ");
    terminal_write_string(APOLLO_BUILD_DATE);
    terminal_write_string(" ");
    terminal_write_string(APOLLO_BUILD_TIME);
    terminal_write_string("\n");
    terminal_write_string("Architecture: ");
    terminal_write_string(APOLLO_ARCH);
    terminal_write_string("\n");

    #ifdef __GNUC__
        terminal_write_string("Compiler: GCC ");
        terminal_write_string(__VERSION__);
        terminal_write_string("\n");
    #endif

    terminal_write_string("\nSystem Palette: ");
    for (int i = 0; i < 16; i++) {
        terminal_set_color(i, i);
        terminal_write_char(' ');
    }
    terminal_set_color(7, 0);
    terminal_write_string("\n\n");
}

static void apollo_system_update_audio(void) {
    audio_update_shell_player();

}

static void apollo_initialize_audio_system_safe(void) {
    terminal_write_string("Initializing audio subsystem\n");

    uint32_t start_time = get_system_time();
    bool audio_success = false;

    // Audio is only used if init finishes within a second
    audio_success = audio_subsystem_initialize();

    uint32_t elapsed = get_system_time() - start_time;

    if (audio_success && elapsed < 1000) {
        terminal_set_color(10, 0);
        terminal_write_string("Audio System: Ready\n");
        terminal_set_color(7, 0);

        if (audio_subsystem_self_test()) {
            terminal_write_string("Audio Self-Test: Passed\n");
        }

        if (filesystem_create_directory("/dev/audio")) {
            filesystem_create_file("/dev/audio/pcm0");
            filesystem_create_file("/dev/audio/mixer");
            filesystem_create_file("/dev/audio/dsp");
            terminal_write_string("Audio device files created\n");
        }

        uint32_t device_count = audio_get_device_count();
        if (device_count > 0) {
            audio_set_master_volume(75);
            audio_set_mute(false);
            terminal_write_string("Audio configured\n");
        }
    } else {
        terminal_set_color(14, 0);
        terminal_write_string("Audio System: Initialization skipped (no compatible hardware)\n");
        terminal_set_color(7, 0);
    }
}

static void apollo_initialize_all_systems(void) {
    terminal_write_string("Initializing Apollo Operating System...\n");

    memory_initialize();
    cpu_initialize();
    program_initialize();
    heap_allocator_initialize();

    time_keeper_initialize();
    system_state.boot_time = time_keeper_get_uptime_seconds();

    filesystem_initialize();
    filesystem_add_boot_modules();

    process_manager_initialize();
    create_kernel_tasks();

    terminal_initialize();

    input_manager_initialize();

    text_editor_initialize();

    network_interface_manager_initialize();
    ip_stack_initialize();
    dhcp_client_initialize();
    dns_client_initialize();
    rtl8139_driver_initialize();
    network_manager_initialize();

    apollo_initialize_audio_system_safe();

    command_processor_initialize();

    uint32_t heap_total = heap_allocator_get_total_memory();
    fs_stats_t fs_stats;
    filesystem_get_stats(&fs_stats);
    process_stats_t proc_stats;
    process_get_stats(&proc_stats);

    bool systems_ok = (heap_total > 0) &&
                      (fs_stats.total_directories > 0) &&
                      (proc_stats.total_processes > 0);

    system_state.all_systems_ready = systems_ok;

    if (systems_ok) {
        terminal_set_color(10, 0); // Green

        apollo_display_startup_sequence();

        terminal_write_string("\nSystem Status:\n");
        terminal_write_string("  Memory Available:  ");
        terminal_write_uint(heap_allocator_get_free_memory() / 1024);
        terminal_write_string(" KB\n");
        terminal_write_string("  Files Available:   ");
        terminal_write_uint(fs_stats.total_files);
        terminal_write_string(" files in ");
        terminal_write_uint(fs_stats.total_directories);
        terminal_write_string(" directories\n");
        terminal_write_string("  Kernel Tasks:      ");
        terminal_write_uint(proc_stats.total_processes);
        terminal_write_string("\n");
        terminal_write_string("  Free Disk Space:   ");
        terminal_write_uint(filesystem_get_free_space() / 1024);
        terminal_write_string(" KB\n");

        terminal_write_string("\nQuick Start Commands:\n");
        terminal_set_color(11, 0); // Light cyan
        terminal_write_string("  help        ");
        terminal_set_color(7, 0);
        terminal_write_string("- Complete command reference\n");
        terminal_set_color(11, 0);
        terminal_write_string("  edit        ");
        terminal_set_color(7, 0);
        terminal_write_string("- Text editor with real file I/O\n");
        terminal_set_color(11, 0);
        terminal_write_string("  dhcp eth0   ");
        terminal_set_color(7, 0);
        terminal_write_string("- Setup and connect to the eth0\n");
        terminal_set_color(11, 0);
        terminal_write_string("  nettest     ");
        terminal_set_color(7, 0);
        terminal_write_string("- Test network connectivity\n");
        terminal_set_color(11, 0);
        terminal_write_string("  audiotest   ");
        terminal_set_color(7, 0);
        terminal_write_string("- Test audio hardware\n");
        terminal_write_string("\n");
        terminal_set_color(7, 0);

    } else {
        terminal_set_color(12, 0); // Red
        terminal_write_string("CRITICAL ERROR: System initialization failed\n");
        terminal_set_color(7, 0);
    }

    terminal_write_string("apollo> ");
    terminal_enable_cursor();
}

static void cpu_relax(void) {
    for (volatile int i = 0; i < 500; i++) {
        __asm__ volatile("pause");
    }
}

static uint32_t task_shell;
static uint32_t task_network;
static uint32_t task_audio;
static uint32_t task_security;

static void create_kernel_tasks(void) {
    task_shell = process_create("shell", PROCESS_TYPE_SYSTEM, (void*)command_processor_handle_input);
    task_network = process_create("network", PROCESS_TYPE_SYSTEM, (void*)network_manager_periodic_tasks);
    task_audio = process_create("audio", PROCESS_TYPE_SYSTEM, (void*)audio_update_shell_player);
    task_security = process_create("security", PROCESS_TYPE_SYSTEM, (void*)firewall_process_timers);
}

static void network_work(void) {
    network_manager_periodic_tasks();
    network_manager_process_packets();
}

static void security_work(void) {
    firewall_process_timers();
    rate_limiter_process_timers();
    secure_boot_periodic();
    security_audit_periodic();
}

// Charges the time spent in work to its task, and skips tasks that were suspended
static void run_task(uint32_t pid, void (*work)(void)) {
    if (!process_is_runnable(pid)) return;
    process_account_begin(pid);
    work();
    process_account_end();
}

static void update_system_activity(void) {
    run_task(task_network, network_work);
    run_task(task_security, security_work);
    run_task(task_audio, apollo_system_update_audio);
}

void apollo_kernel_main(void) {

    terminal_initialize();

    apollo_initialize_all_systems();

    if (!system_state.all_systems_ready) {
        terminal_set_color(12, 0);
        terminal_write_string("FATAL: Cannot start system - initialization failed\n");
        terminal_set_color(7, 0);

        __asm__ __volatile__("cli; hlt");
        return;
    }

    uint32_t activity_counter = 0;

    while (1) {
        if (input_manager_has_input()) {
            uint8_t scan_code = input_manager_read_scancode();
            process_account_begin(task_shell);
            command_processor_handle_input(scan_code);
            process_account_end();
        }

        activity_counter++;
        if (activity_counter >= 10000) {
            update_system_activity();
            activity_counter = 0;
        }

        cpu_relax();
    }
}
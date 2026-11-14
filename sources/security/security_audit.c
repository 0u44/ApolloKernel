#include "security_audit.h"
#include "crypto.h"
#include "firewall.h"
#include "rate_limiter.h"
#include "secure_boot.h"
#include "ip_stack.h"
#include "network_interface.h"
#include "command_processor.h"
#include "heap_allocator.h"
#include "terminal.h"
#include "string_utils.h"
#include "time_keeper.h"

#define CR0_WRITE_PROTECT (1UL << 16)
#define CR4_SMEP (1UL << 20)
#define CR4_SMAP (1UL << 21)
#define MSR_EFER 0xC0000080
#define EFER_NXE (1UL << 11)
#define CPUID_EXTENDED_FEATURES 7
#define CPUID7_EBX_SMEP (1U << 7)
#define CPUID7_EBX_SMAP (1U << 20)
#define CPUID_EXT_MAX 0x80000000
#define CPUID_EXT_FEATURES 0x80000001
#define CPUID_EXT_EDX_NX (1U << 20)
#define HEAP_WARN_PERCENT 90
#define MAX_OPEN_PORTS 32
#define MONITOR_INTERVAL_MS 60000
#define PENALTY_CRITICAL 25
#define PENALTY_HIGH 15
#define PENALTY_MEDIUM 8
#define PENALTY_LOW 3
#define FULL_SCORE 100

#define SCAN_CRYPTO 0x01
#define SCAN_BOOT 0x02
#define SCAN_NETWORK 0x04
#define SCAN_CPU 0x08
#define SCAN_SYSTEM 0x10
#define SCAN_FULL (SCAN_CRYPTO | SCAN_BOOT | SCAN_NETWORK | SCAN_CPU | SCAN_SYSTEM)
#define SCAN_QUICK (SCAN_BOOT | SCAN_NETWORK | SCAN_CPU)

static bool audit_initialized = false;
static bool monitoring = false;
static security_audit_result_t current_result;
static uint32_t monitor_baseline_serious = 0;

static void add_issue(security_audit_result_t* r, security_severity_t severity, security_category_t category,
                      const char* title, const char* description, const char* recommendation, bool exploitable) {
    if (r->issue_count >= SECURITY_AUDIT_MAX_ISSUES) return;
    security_issue_t* issue = &r->issues[r->issue_count];
    issue->issue_id = r->issue_count + 1;
    issue->severity = severity;
    issue->category = category;
    string_copy_n(issue->title, title, sizeof(issue->title));
    string_copy_n(issue->description, description, sizeof(issue->description));
    string_copy_n(issue->recommendation, recommendation, sizeof(issue->recommendation));
    issue->is_exploitable = exploitable;
    issue->risk_score = (severity == SECURITY_SEVERITY_CRITICAL) ? 90 : (uint32_t)severity * 20;
    r->issue_count++;
    switch (severity) {
        case SECURITY_SEVERITY_CRITICAL: r->critical_count++; break;
        case SECURITY_SEVERITY_HIGH: r->high_count++; break;
        case SECURITY_SEVERITY_MEDIUM: r->medium_count++; break;
        case SECURITY_SEVERITY_LOW: r->low_count++; break;
        case SECURITY_SEVERITY_INFO: r->info_count++; break;
    }
}

static void check_crypto(security_audit_result_t* r) {
    if (!crypto_self_test()) {
        add_issue(r, SECURITY_SEVERITY_CRITICAL, SECURITY_CAT_ENCRYPTION, "Crypto known answer tests fail",
                  "SHA-256, SHA-512, AES or HMAC output differs from the published test vectors.",
                  "Do not use crypto until crypto test passes.", true);
    }
    uint8_t sources = crypto_get_entropy_sources();
    if (!(sources & (CRYPTO_ENTROPY_RDRAND | CRYPTO_ENTROPY_RDSEED))) {
        add_issue(r, SECURITY_SEVERITY_MEDIUM, SECURITY_CAT_ENCRYPTION, "No hardware entropy source",
                  "The CPU reports neither RDRAND nor RDSEED, random numbers come from timing jitter only.",
                  "Run on a CPU with RDRAND, or pass -cpu host under QEMU.", false);
    }
}

static void check_boot(security_audit_result_t* r) {
    secure_boot_state_t state = secure_boot_get_state();
    if (state == SECURE_BOOT_STATE_FAILED) {
        add_issue(r, SECURITY_SEVERITY_CRITICAL, SECURITY_CAT_SYSTEM, "Kernel does not match build reference",
                  "The SHA-256 of .text and .rodata at boot differs from the hash embedded at build time.",
                  "Rebuild the kernel and compare with secureboot measurements.", true);
    } else if (state == SECURE_BOOT_STATE_UNVERIFIED) {
        add_issue(r, SECURITY_SEVERITY_HIGH, SECURITY_CAT_SYSTEM, "Kernel not verified",
                  "No build reference hash is embedded, so the kernel image cannot be checked.",
                  "Build with the Makefile so the reference is written into .secureboot.", false);
    }
    if (!secure_boot_check_runtime_integrity()) {
        add_issue(r, SECURITY_SEVERITY_CRITICAL, SECURITY_CAT_SYSTEM, "Kernel code changed after boot",
                  "The kernel image hash no longer matches the measurement taken at boot.",
                  "Reboot from a known good image.", true);
    }
}

static void check_firewall(security_audit_result_t* r) {
    if (!firewall_is_enabled()) {
        add_issue(r, SECURITY_SEVERITY_HIGH, SECURITY_CAT_NETWORK, "Firewall disabled",
                  "Inbound packets are delivered to every protocol handler without filtering.",
                  "Run firewall enable.", true);
    } else if (firewall_get_default_policy(FIREWALL_DIR_IN) == FIREWALL_ACTION_ALLOW) {
        add_issue(r, SECURITY_SEVERITY_MEDIUM, SECURITY_CAT_NETWORK, "Firewall allows inbound by default",
                  "Packets that match no rule are accepted.",
                  "Run firewall default in deny.", true);
    }
    if (!rate_limiter_is_enabled() || rate_limiter_get_rule_count() == 0) {
        add_issue(r, SECURITY_SEVERITY_LOW, SECURITY_CAT_NETWORK, "No rate limiting",
                  "Inbound packet rates are not limited.",
                  "Run ratelimit ddos and ratelimit enable.", false);
    }
}

static void check_open_ports(security_audit_result_t* r) {
    uint16_t ports[MAX_OPEN_PORTS];
    uint32_t count = udp_list_bound_ports(ports, MAX_OPEN_PORTS);
    for (uint32_t i = 0; i < count; i++) {
        char title[48];
        char digits[6];
        uint32_t value = ports[i];
        int n = 0;
        do { digits[n++] = (char)('0' + value % 10); value /= 10; } while (value);
        string_copy(title, "UDP port open: ");
        uint32_t pos = string_length(title);
        while (n > 0) title[pos++] = digits[--n];
        title[pos] = '\0';
        add_issue(r, SECURITY_SEVERITY_INFO, SECURITY_CAT_NETWORK, title,
                  "A socket is bound to this port and receives packets.", "Close the socket if it is unused.", false);
    }
}

static uint64_t read_cr0(void) {
    uint64_t value;
    __asm__ volatile("mov %%cr0, %0" : "=r"(value));
    return value;
}

static uint64_t read_cr4(void) {
    uint64_t value;
    __asm__ volatile("mov %%cr4, %0" : "=r"(value));
    return value;
}

static uint64_t read_msr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static void cpuid(uint32_t leaf, uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    __asm__ volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "a"(leaf), "c"(0));
}

// Reads the protection bits the CPU is actually running with
static void check_cpu(security_audit_result_t* r) {
    uint32_t a, b, c, d;
    if (!(read_cr0() & CR0_WRITE_PROTECT)) {
        add_issue(r, SECURITY_SEVERITY_MEDIUM, SECURITY_CAT_SYSTEM, "CR0.WP is clear",
                  "Kernel code can write to read only pages.", "Set CR0.WP during boot.", false);
    }
    cpuid(CPUID_EXT_MAX, &a, &b, &c, &d);
    bool nx_supported = false;
    if (a >= CPUID_EXT_FEATURES) {
        cpuid(CPUID_EXT_FEATURES, &a, &b, &c, &d);
        nx_supported = (d & CPUID_EXT_EDX_NX) != 0;
    }
    if (nx_supported && !(read_msr(MSR_EFER) & EFER_NXE)) {
        add_issue(r, SECURITY_SEVERITY_MEDIUM, SECURITY_CAT_SYSTEM, "No-execute is off",
                  "EFER.NXE is clear, so every mapped page is executable including the heap and stack.",
                  "Set EFER.NXE and mark data pages NX.", true);
    }
    cpuid(0, &a, &b, &c, &d);
    if (a < CPUID_EXTENDED_FEATURES) return;
    cpuid(CPUID_EXTENDED_FEATURES, &a, &b, &c, &d);
    uint64_t cr4 = read_cr4();
    if ((b & CPUID7_EBX_SMEP) && !(cr4 & CR4_SMEP)) {
        add_issue(r, SECURITY_SEVERITY_LOW, SECURITY_CAT_SYSTEM, "SMEP supported but off",
                  "CR4.SMEP is clear on a CPU that supports it.", "Set CR4.SMEP.", false);
    }
    if ((b & CPUID7_EBX_SMAP) && !(cr4 & CR4_SMAP)) {
        add_issue(r, SECURITY_SEVERITY_LOW, SECURITY_CAT_SYSTEM, "SMAP supported but off",
                  "CR4.SMAP is clear on a CPU that supports it.", "Set CR4.SMAP.", false);
    }
}

static void check_system(security_audit_result_t* r) {
    char description[128];
    string_copy(description, "The shell starts as '");
    string_concat_n(description, command_processor_get_current_user(), sizeof(description));
    string_concat_n(description, "' with no login prompt or password.", sizeof(description));
    add_issue(r, SECURITY_SEVERITY_MEDIUM, SECURITY_CAT_AUTHENTICATION, "No login before shell access",
              description, "Add a login step before the shell starts.", false);

    size_t total = heap_allocator_get_total_memory();
    if (total > 0 && heap_allocator_get_used_memory() * 100 / total >= HEAP_WARN_PERCENT) {
        add_issue(r, SECURITY_SEVERITY_MEDIUM, SECURITY_CAT_SYSTEM, "Heap nearly full",
                  "Kernel heap usage is at or above 90 percent.", "Free unused buffers.", false);
    }
}

static security_audit_result_t* run_scan(uint32_t checks, const char* version) {
    if (!audit_initialized) return NULL;
    for (uint32_t i = 0; i < sizeof(current_result); i++) ((uint8_t*)&current_result)[i] = 0;
    if (checks & SCAN_CRYPTO) check_crypto(&current_result);
    if (checks & SCAN_BOOT) check_boot(&current_result);
    if (checks & SCAN_NETWORK) {
        check_firewall(&current_result);
        check_open_ports(&current_result);
    }
    if (checks & SCAN_CPU) check_cpu(&current_result);
    if (checks & SCAN_SYSTEM) check_system(&current_result);

    int32_t score = FULL_SCORE - (int32_t)(current_result.critical_count * PENALTY_CRITICAL +
                                           current_result.high_count * PENALTY_HIGH +
                                           current_result.medium_count * PENALTY_MEDIUM +
                                           current_result.low_count * PENALTY_LOW);
    current_result.overall_score = score < 0 ? 0 : (uint32_t)score;
    current_result.audit_passed = current_result.critical_count == 0 && current_result.high_count == 0;
    current_result.audit_time = get_system_time();
    string_copy(current_result.audit_version, version);
    return &current_result;
}

bool security_audit_initialize(void) {
    audit_initialized = true;
    return true;
}

security_audit_result_t* security_audit_run_full_scan(void) {
    return run_scan(SCAN_FULL, "Full scan");
}

security_audit_result_t* security_audit_run_quick_scan(void) {
    return run_scan(SCAN_QUICK, "Quick scan");
}

security_audit_result_t* security_audit_run_network_scan(void) {
    return run_scan(SCAN_NETWORK, "Network scan");
}

static void print_count(const char* label, uint32_t count, uint8_t color) {
    if (count == 0) return;
    terminal_set_color(color, 0);
    terminal_write_string(label);
    terminal_write_uint(count);
    terminal_set_color(7, 0);
    terminal_write_string("\n");
}

void security_audit_print_summary(const security_audit_result_t* result) {
    if (!result) {
        terminal_write_string("No audit results, the audit system is not initialized\n");
        return;
    }
    terminal_write_string("\n=== SECURITY AUDIT: ");
    terminal_write_string(result->audit_version);
    terminal_write_string(" ===\nScore: ");
    terminal_set_color(result->overall_score >= 80 ? 10 : (result->overall_score >= 60 ? 14 : 12), 0);
    terminal_write_uint(result->overall_score);
    terminal_write_string("/100");
    terminal_set_color(7, 0);
    terminal_write_string("  Issues: ");
    terminal_write_uint(result->issue_count);
    terminal_write_string("\n");
    print_count("  Critical: ", result->critical_count, 12);
    print_count("  High: ", result->high_count, 14);
    print_count("  Medium: ", result->medium_count, 11);
    print_count("  Low: ", result->low_count, 7);
    print_count("  Info: ", result->info_count, 9);
    for (uint32_t i = 0; i < result->issue_count; i++) {
        if (result->issues[i].severity < SECURITY_SEVERITY_MEDIUM) continue;
        terminal_write_string("  - ");
        terminal_write_string(result->issues[i].title);
        terminal_write_string("\n");
    }
    terminal_write_string("Result: ");
    terminal_set_color(result->audit_passed ? 10 : 12, 0);
    terminal_write_string(result->audit_passed ? "PASSED\n" : "FAILED\n");
    terminal_set_color(7, 0);
}

static const char* severity_name(security_severity_t severity) {
    static const char* names[] = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    return (uint32_t)severity <= SECURITY_SEVERITY_CRITICAL ? names[severity] : "UNKNOWN";
}

void security_audit_print_detailed_report(const security_audit_result_t* result) {
    security_audit_print_summary(result);
    if (!result) return;
    for (uint32_t i = 0; i < result->issue_count; i++) {
        const security_issue_t* issue = &result->issues[i];
        terminal_write_string("\n[");
        terminal_write_string(severity_name(issue->severity));
        terminal_write_string("] ");
        terminal_write_string(issue->title);
        terminal_write_string(issue->is_exploitable ? "  (exploitable)\n  " : "\n  ");
        terminal_write_string(issue->description);
        terminal_write_string("\n  Fix: ");
        terminal_write_string(issue->recommendation);
        terminal_write_string("\n");
    }
}

static uint32_t serious_issue_count(const security_audit_result_t* r) {
    return r ? r->critical_count + r->high_count : 0;
}

bool security_audit_start_continuous_monitoring(void) {
    if (!audit_initialized) return false;
    monitor_baseline_serious = serious_issue_count(security_audit_run_quick_scan());
    monitoring = true;
    return true;
}

void security_audit_stop_continuous_monitoring(void) {
    monitoring = false;
}

void security_audit_periodic(void) {
    static uint32_t last_run = 0;
    if (!monitoring) return;
    uint32_t now = get_system_time();
    if (now - last_run < MONITOR_INTERVAL_MS) return;
    last_run = now;
    security_audit_result_t* result = security_audit_run_quick_scan();
    uint32_t serious = serious_issue_count(result);
    if (serious > monitor_baseline_serious) {
        terminal_set_color(12, 0);
        terminal_write_string("SECURITY_AUDIT: new high or critical findings, run secaudit --detailed\n");
        terminal_set_color(7, 0);
    }
    monitor_baseline_serious = serious;
}
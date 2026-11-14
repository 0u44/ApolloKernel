#include "secure_boot.h"
#include "crypto.h"
#include "heap_allocator.h"
#include "terminal.h"
#include "string_utils.h"
#include "time_keeper.h"

#define PCR_COUNT 24
#define PCR_FIRMWARE 0
#define PCR_CONFIG 1
#define PCR_DRIVER 2
#define PCR_BOOTLOADER 4
#define PCR_KERNEL 8
#define PCR_INITRD 9
#define PCR_APPLICATION 10
#define PCR_SELF_TEST 23
#define PLATFORM_KEY_MAX 64
#define HMAC_SIZE 32
#define FIRMWARE_ROM_BASE 0xF0000
#define FIRMWARE_ROM_SIZE 0x10000
#define MONITOR_INTERVAL_MS 30000
#define CPUID_BRAND_FIRST 0x80000002
#define CPUID_BRAND_LAST 0x80000004
#define POLICY_PERMISSIVE "permissive"
#define POLICY_STRICT "strict"

extern const uint8_t __text_start[];
extern const uint8_t __text_end[];
extern const uint8_t __rodata_start[];
extern const uint8_t __rodata_end[];

// The build hashes .text and .rodata and writes the result here after linking
__attribute__((section(".secureboot"), used, aligned(16)))
static volatile const uint8_t kernel_reference[SECURE_BOOT_HASH_SIZE] = {0};

static uint8_t pcrs[PCR_COUNT][SECURE_BOOT_HASH_SIZE];
static bool pcr_locked[PCR_COUNT];
static boot_measurement_t measurements[SECURE_BOOT_MAX_MEASUREMENTS];
static uint32_t measurement_count = 0;
static boot_component_t components[SECURE_BOOT_MAX_COMPONENTS];
static uint32_t component_count = 0;
static secure_boot_certificate_t certificates[SECURE_BOOT_MAX_CERTS];
static uint32_t certificate_count = 0;
static uint8_t platform_key[PLATFORM_KEY_MAX];
static uint32_t platform_key_size = 0;
static uint8_t kernel_boot_hash[SECURE_BOOT_HASH_SIZE];
static bool kernel_reference_present = false;
static bool kernel_matches_reference = false;
static secure_boot_state_t boot_state = SECURE_BOOT_STATE_UNVERIFIED;
static bool secure_boot_initialized = false;
static bool setup_mode = true;
static bool runtime_monitoring = false;
static uint32_t boot_time = 0;
static char policy[32] = POLICY_PERMISSIVE;

static struct {
    uint8_t pcrs[PCR_COUNT][SECURE_BOOT_HASH_SIZE];
    boot_measurement_t measurements[SECURE_BOOT_MAX_MEASUREMENTS];
    uint32_t measurement_count;
    bool valid;
} backup;

static void copy_bytes(void* dest, const void* src, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < size; i++) d[i] = s[i];
}

static void zero_bytes(void* dest, uint32_t size) {
    crypto_secure_zero(dest, size);
}

static bool bytes_equal(const uint8_t* a, const uint8_t* b, uint32_t size) {
    return crypto_secure_compare(a, b, size);
}

static bool is_zero(const uint8_t* data, uint32_t size) {
    uint8_t acc = 0;
    for (uint32_t i = 0; i < size; i++) acc |= data[i];
    return acc == 0;
}

static void write_hash(const uint8_t* hash) {
    const char hex[] = "0123456789abcdef";
    for (uint32_t i = 0; i < SECURE_BOOT_HASH_SIZE; i++) {
        terminal_write_char(hex[hash[i] >> 4]);
        terminal_write_char(hex[hash[i] & 0x0F]);
    }
}

static uint8_t pcr_for_type(boot_component_type_t type) {
    switch (type) {
        case BOOT_COMPONENT_FIRMWARE: return PCR_FIRMWARE;
        case BOOT_COMPONENT_CONFIG: return PCR_CONFIG;
        case BOOT_COMPONENT_DRIVER: return PCR_DRIVER;
        case BOOT_COMPONENT_BOOTLOADER: return PCR_BOOTLOADER;
        case BOOT_COMPONENT_KERNEL: return PCR_KERNEL;
        case BOOT_COMPONENT_INITRD: return PCR_INITRD;
        case BOOT_COMPONENT_APPLICATION: return PCR_APPLICATION;
    }
    return PCR_APPLICATION;
}

static const char* type_name(boot_component_type_t type) {
    static const char* names[] = {"Firmware", "Bootloader", "Kernel", "Initrd", "Driver", "Config", "Application"};
    return (uint32_t)type <= BOOT_COMPONENT_APPLICATION ? names[type] : "Unknown";
}

static bool sign_hash(const uint8_t* hash, uint8_t* signature) {
    if (platform_key_size == 0) return false;
    return crypto_hmac(CRYPTO_HASH_SHA256, platform_key, platform_key_size, hash, SECURE_BOOT_HASH_SIZE, signature);
}

static bool signature_valid(const uint8_t* hash, const uint8_t* signature) {
    uint8_t expected[HMAC_SIZE];
    bool ok = sign_hash(hash, expected) && bytes_equal(expected, signature, HMAC_SIZE);
    zero_bytes(expected, sizeof(expected));
    return ok;
}

static uint32_t kernel_image_size(void) {
    return (uint32_t)((__text_end - __text_start) + (__rodata_end - __rodata_start));
}

static void hash_kernel_image(uint8_t* out) {
    crypto_sha256_context_t ctx;
    crypto_sha256_init(&ctx);
    crypto_sha256_update(&ctx, __text_start, (uint32_t)(__text_end - __text_start));
    crypto_sha256_update(&ctx, __rodata_start, (uint32_t)(__rodata_end - __rodata_start));
    crypto_sha256_final(&ctx, out);
    crypto_sha256_destroy(&ctx);
}

bool secure_boot_pcr_extend(uint8_t pcr_index, const uint8_t* data, uint32_t data_size) {
    if (pcr_index >= PCR_COUNT || !data || data_size == 0 || pcr_locked[pcr_index]) return false;
    uint8_t digest[SECURE_BOOT_HASH_SIZE];
    uint8_t joined[SECURE_BOOT_HASH_SIZE * 2];
    if (!crypto_sha256(data, data_size, digest)) return false;
    copy_bytes(joined, pcrs[pcr_index], SECURE_BOOT_HASH_SIZE);
    copy_bytes(joined + SECURE_BOOT_HASH_SIZE, digest, SECURE_BOOT_HASH_SIZE);
    return crypto_sha256(joined, sizeof(joined), pcrs[pcr_index]);
}

bool secure_boot_pcr_read(uint8_t pcr_index, uint8_t* pcr_value) {
    if (pcr_index >= PCR_COUNT || !pcr_value) return false;
    copy_bytes(pcr_value, pcrs[pcr_index], SECURE_BOOT_HASH_SIZE);
    return true;
}

bool secure_boot_pcr_reset(uint8_t pcr_index) {
    if (pcr_index >= PCR_COUNT || pcr_locked[pcr_index]) return false;
    zero_bytes(pcrs[pcr_index], SECURE_BOOT_HASH_SIZE);
    return true;
}

void secure_boot_pcr_lock(uint8_t pcr_index) {
    if (pcr_index < PCR_COUNT) pcr_locked[pcr_index] = true;
}

static boot_component_t* find_component(boot_component_type_t type, const char* name) {
    for (uint32_t i = 0; i < component_count; i++) {
        if (components[i].type == type && (!name || string_equals(components[i].name, name))) {
            return &components[i];
        }
    }
    return NULL;
}

static boot_measurement_t* record_measurement(boot_component_type_t type, const char* name,
                                              const uint8_t* hash, uint32_t size, uint32_t address) {
    if (measurement_count >= SECURE_BOOT_MAX_MEASUREMENTS) return NULL;
    boot_measurement_t* m = &measurements[measurement_count++];
    zero_bytes(m, sizeof(*m));
    m->component_type = type;
    string_copy(m->component_name, name);
    copy_bytes(m->measurement, hash, SECURE_BOOT_HASH_SIZE);
    m->component_size = size;
    m->load_address = address;
    m->measurement_time = get_system_time();
    m->is_critical = (type == BOOT_COMPONENT_KERNEL || type == BOOT_COMPONENT_BOOTLOADER);
    boot_component_t* enrolled = find_component(type, name);
    if (enrolled) {
        copy_bytes(m->expected_hash, enrolled->hash, SECURE_BOOT_HASH_SIZE);
        m->is_verified = bytes_equal(hash, enrolled->hash, SECURE_BOOT_HASH_SIZE);
    }
    return m;
}

bool secure_boot_measure_component(boot_component_type_t type, const char* name,
                                  const void* data, uint32_t size) {
    if (!name || !data || size == 0) return false;
    uint8_t hash[SECURE_BOOT_HASH_SIZE];
    if (!crypto_sha256((const uint8_t*)data, size, hash)) return false;
    if (!secure_boot_pcr_extend(pcr_for_type(type), hash, sizeof(hash))) return false;
    return record_measurement(type, name, hash, size, (uint32_t)(uintptr_t)data) != NULL;
}

// Measures firmware and the kernel image, then compares the kernel against the build reference
static void measure_boot_chain(void) {
    secure_boot_measure_component(BOOT_COMPONENT_FIRMWARE, "BIOS ROM",
                                  (const void*)(uintptr_t)FIRMWARE_ROM_BASE, FIRMWARE_ROM_SIZE);

    hash_kernel_image(kernel_boot_hash);
    secure_boot_pcr_extend(PCR_KERNEL, kernel_boot_hash, sizeof(kernel_boot_hash));
    boot_measurement_t* m = record_measurement(BOOT_COMPONENT_KERNEL, "kernel text and rodata", kernel_boot_hash,
                                               kernel_image_size(), (uint32_t)(uintptr_t)__text_start);

    uint8_t reference[SECURE_BOOT_HASH_SIZE];
    for (uint32_t i = 0; i < SECURE_BOOT_HASH_SIZE; i++) reference[i] = kernel_reference[i];
    kernel_reference_present = !is_zero(reference, sizeof(reference));
    kernel_matches_reference = kernel_reference_present && bytes_equal(reference, kernel_boot_hash, sizeof(reference));
    if (m && kernel_reference_present) {
        copy_bytes(m->expected_hash, reference, sizeof(reference));
        m->is_verified = kernel_matches_reference;
    }

    if (!kernel_reference_present) {
        boot_state = SECURE_BOOT_STATE_UNVERIFIED;
    } else {
        boot_state = kernel_matches_reference ? SECURE_BOOT_STATE_VERIFIED : SECURE_BOOT_STATE_FAILED;
    }
}

bool secure_boot_early_init(void) {
    boot_state = SECURE_BOOT_STATE_VERIFYING;
    boot_time = get_system_time();
    return true;
}

bool secure_boot_initialize(void) {
    if (secure_boot_initialized) return true;
    if (boot_time == 0) boot_time = get_system_time();
    secure_boot_initialized = true;
    measure_boot_chain();
    terminal_write_string("SECURE_BOOT: kernel ");
    if (boot_state == SECURE_BOOT_STATE_VERIFIED) {
        terminal_write_string("matches the build reference\n");
    } else if (boot_state == SECURE_BOOT_STATE_FAILED) {
        terminal_write_string("does not match the build reference\n");
    } else {
        terminal_write_string("measured, no build reference embedded\n");
    }
    return true;
}

void secure_boot_shutdown(void) {
    secure_boot_initialized = false;
    runtime_monitoring = false;
}

bool secure_boot_load_platform_key(const uint8_t* key_data, uint32_t key_size) {
    if (!key_data || key_size == 0 || key_size > PLATFORM_KEY_MAX) return false;
    if (platform_key_size != 0 && !setup_mode) return false;
    copy_bytes(platform_key, key_data, key_size);
    platform_key_size = key_size;
    setup_mode = false;
    return true;
}

static secure_boot_certificate_t* find_certificate(const uint8_t* subject_hash) {
    for (uint32_t i = 0; i < certificate_count; i++) {
        if (bytes_equal(certificates[i].subject_hash, subject_hash, SECURE_BOOT_HASH_SIZE)) {
            return &certificates[i];
        }
    }
    return NULL;
}

// Certificates are signed with HMAC-SHA256 keyed by the issuer key, RSA is not in the kernel
static bool certificate_signature_valid(const secure_boot_certificate_t* cert, const secure_boot_certificate_t* issuer) {
    uint8_t message[SECURE_BOOT_HASH_SIZE + sizeof(uint32_t)];
    uint8_t expected[HMAC_SIZE];
    copy_bytes(message, cert->subject_hash, SECURE_BOOT_HASH_SIZE);
    copy_bytes(message + SECURE_BOOT_HASH_SIZE, &cert->serial_number, sizeof(uint32_t));
    uint32_t key_size = issuer->key_size > sizeof(issuer->public_key) ? sizeof(issuer->public_key) : issuer->key_size;
    bool ok = key_size > 0 &&
              crypto_hmac(CRYPTO_HASH_SHA256, issuer->public_key, key_size, message, sizeof(message), expected) &&
              bytes_equal(expected, cert->signature, HMAC_SIZE);
    zero_bytes(expected, sizeof(expected));
    return ok;
}

static bool certificate_time_valid(const secure_boot_certificate_t* cert) {
    uint64_t now = time_keeper_get_unix_time();
    return now >= cert->valid_from && (cert->valid_until == 0 || now <= cert->valid_until);
}

bool secure_boot_verify_certificate_chain(const secure_boot_certificate_t* cert) {
    const secure_boot_certificate_t* current = cert;
    for (uint32_t depth = 0; current && depth <= SECURE_BOOT_MAX_CERTS; depth++) {
        if (current->is_revoked || !certificate_time_valid(current)) return false;
        bool self_signed = bytes_equal(current->subject_hash, current->issuer_hash, SECURE_BOOT_HASH_SIZE);
        const secure_boot_certificate_t* issuer = self_signed ? current : find_certificate(current->issuer_hash);
        if (!issuer || !issuer->is_ca || issuer->is_revoked) return false;
        if (!certificate_signature_valid(current, issuer)) return false;
        if (self_signed) return current->is_trusted;
        current = issuer;
    }
    return false;
}

bool secure_boot_add_certificate(const secure_boot_certificate_t* cert) {
    if (!cert || certificate_count >= SECURE_BOOT_MAX_CERTS || find_certificate(cert->subject_hash)) return false;
    if (!setup_mode && !secure_boot_verify_certificate_chain(cert)) return false;
    certificates[certificate_count++] = *cert;
    return true;
}

bool secure_boot_revoke_certificate(const uint8_t* cert_hash) {
    secure_boot_certificate_t* cert = cert_hash ? find_certificate(cert_hash) : NULL;
    if (!cert) return false;
    cert->is_revoked = true;
    cert->is_trusted = false;
    return true;
}

bool secure_boot_add_component(const boot_component_t* component) {
    if (!component || component_count >= SECURE_BOOT_MAX_COMPONENTS || !setup_mode) return false;
    if (find_component(component->type, component->name)) return false;
    components[component_count] = *component;
    components[component_count].data = NULL;
    component_count++;
    return true;
}

bool secure_boot_verify_component(boot_component_t* component) {
    if (!component || !component->data || component->size == 0) return false;
    uint8_t hash[SECURE_BOOT_HASH_SIZE];
    if (!crypto_sha256(component->data, component->size, hash)) return false;
    copy_bytes(component->hash, hash, sizeof(hash));
    boot_component_t* enrolled = find_component(component->type, component->name);
    component->is_verified = enrolled && bytes_equal(hash, enrolled->hash, sizeof(hash));
    bool signature_ok = !component->is_signed ||
                        (component->signature_size == HMAC_SIZE && signature_valid(hash, component->signature));
    component->is_trusted = component->is_verified && signature_ok;
    return component->is_trusted;
}

static bool verify_buffer(boot_component_type_t type, const char* name, const void* data, uint32_t size) {
    if (!data || size == 0) return false;
    secure_boot_measure_component(type, name, data, size);
    boot_component_t probe;
    zero_bytes(&probe, sizeof(probe));
    probe.type = type;
    string_copy(probe.name, name);
    probe.data = (uint8_t*)data;
    probe.size = size;
    boot_component_t* enrolled = find_component(type, name);
    if (enrolled) {
        probe.is_signed = enrolled->is_signed;
        probe.signature_size = enrolled->signature_size;
        copy_bytes(probe.signature, enrolled->signature, SECURE_BOOT_SIGNATURE_SIZE);
    }
    return secure_boot_verify_component(&probe);
}

bool secure_boot_verify_bootloader(const void* bootloader_data, uint32_t size) {
    return verify_buffer(BOOT_COMPONENT_BOOTLOADER, "bootloader", bootloader_data, size);
}

// Without arguments the running kernel image is checked against the build reference
bool secure_boot_verify_kernel(const void* kernel_data, uint32_t size) {
    if (!kernel_data) return kernel_matches_reference;
    return verify_buffer(BOOT_COMPONENT_KERNEL, "kernel", kernel_data, size);
}

bool secure_boot_verify_drivers(void) {
    return kernel_matches_reference;
}

secure_boot_state_t secure_boot_get_state(void) {
    return boot_state;
}

bool secure_boot_set_policy(const char* new_policy) {
    if (!new_policy || !setup_mode) return false;
    if (!string_equals(new_policy, POLICY_PERMISSIVE) && !string_equals(new_policy, POLICY_STRICT)) return false;
    string_copy(policy, new_policy);
    return true;
}

const char* secure_boot_get_policy(void) {
    return policy;
}

bool secure_boot_check_policy_compliance(void) {
    if (boot_state == SECURE_BOOT_STATE_COMPROMISED) return false;
    if (!string_equals(policy, POLICY_STRICT)) return true;
    if (boot_state != SECURE_BOOT_STATE_VERIFIED) return false;
    for (uint32_t i = 0; i < measurement_count; i++) {
        if (measurements[i].is_critical && !measurements[i].is_verified) return false;
    }
    return true;
}

bool secure_boot_enter_setup_mode(void) {
    setup_mode = true;
    return true;
}

bool secure_boot_exit_setup_mode(void) {
    if (platform_key_size == 0) return false;
    setup_mode = false;
    return true;
}

bool secure_boot_in_setup_mode(void) {
    return setup_mode;
}

static void read_cpu_brand(char* out, uint32_t size) {
    uint32_t words[12];
    uint32_t max_leaf;
    __asm__ volatile("cpuid" : "=a"(max_leaf) : "a"(0x80000000) : "ebx", "ecx", "edx");
    if (max_leaf < CPUID_BRAND_LAST || size < sizeof(words) + 1) {
        string_copy(out, "x86_64");
        return;
    }
    for (uint32_t leaf = CPUID_BRAND_FIRST; leaf <= CPUID_BRAND_LAST; leaf++) {
        uint32_t* w = &words[(leaf - CPUID_BRAND_FIRST) * 4];
        __asm__ volatile("cpuid" : "=a"(w[0]), "=b"(w[1]), "=c"(w[2]), "=d"(w[3]) : "a"(leaf));
    }
    copy_bytes(out, words, sizeof(words));
    out[sizeof(words)] = '\0';
}

static bool attestation_mac(const secure_boot_attestation_t* a, uint8_t* mac) {
    crypto_hmac_context_t ctx;
    if (platform_key_size == 0 || !crypto_hmac_init(&ctx, CRYPTO_HASH_SHA256, platform_key, platform_key_size)) {
        return false;
    }
    crypto_hmac_update(&ctx, &a->platform_pcrs[0][0], sizeof(a->platform_pcrs));
    crypto_hmac_update(&ctx, &a->boot_measurements[0][0], sizeof(a->boot_measurements));
    crypto_hmac_update(&ctx, (const uint8_t*)&a->measurement_count, sizeof(a->measurement_count));
    crypto_hmac_update(&ctx, (const uint8_t*)&a->boot_state, sizeof(a->boot_state));
    crypto_hmac_update(&ctx, (const uint8_t*)&a->report_time, sizeof(a->report_time));
    crypto_hmac_final(&ctx, mac);
    crypto_hmac_destroy(&ctx);
    return true;
}

bool secure_boot_generate_attestation(secure_boot_attestation_t* attestation) {
    if (!secure_boot_initialized || !attestation) return false;
    zero_bytes(attestation, sizeof(*attestation));
    copy_bytes(attestation->platform_pcrs, pcrs, sizeof(pcrs));
    for (uint32_t i = 0; i < measurement_count; i++) {
        copy_bytes(attestation->boot_measurements[i], measurements[i].measurement, SECURE_BOOT_HASH_SIZE);
    }
    attestation->measurement_count = measurement_count;
    attestation->boot_state = boot_state;
    attestation->boot_time = boot_time;
    attestation->report_time = get_system_time();
    read_cpu_brand(attestation->platform_info, sizeof(attestation->platform_info));
    string_copy(attestation->boot_policy, policy);
    if (attestation_mac(attestation, attestation->attestation_signature)) {
        attestation->signature_size = HMAC_SIZE;
    }
    return true;
}

bool secure_boot_verify_attestation(const secure_boot_attestation_t* attestation) {
    uint8_t mac[HMAC_SIZE];
    if (!attestation || attestation->signature_size != HMAC_SIZE || !attestation_mac(attestation, mac)) return false;
    bool ok = bytes_equal(mac, attestation->attestation_signature, HMAC_SIZE);
    zero_bytes(mac, sizeof(mac));
    return ok;
}

// Quote format is HMAC over the nonce followed by all PCR values
bool secure_boot_remote_attestation(const char* nonce, uint8_t* attestation_data, uint32_t* data_size) {
    crypto_hmac_context_t ctx;
    if (!nonce || !attestation_data || !data_size || *data_size < HMAC_SIZE || platform_key_size == 0) return false;
    if (!crypto_hmac_init(&ctx, CRYPTO_HASH_SHA256, platform_key, platform_key_size)) return false;
    crypto_hmac_update(&ctx, (const uint8_t*)nonce, string_length(nonce));
    crypto_hmac_update(&ctx, &pcrs[0][0], sizeof(pcrs));
    crypto_hmac_final(&ctx, attestation_data);
    crypto_hmac_destroy(&ctx);
    *data_size = HMAC_SIZE;
    return true;
}

bool secure_boot_start_runtime_monitoring(void) {
    if (!secure_boot_initialized) return false;
    runtime_monitoring = true;
    return true;
}

void secure_boot_stop_runtime_monitoring(void) {
    runtime_monitoring = false;
}

bool secure_boot_check_runtime_integrity(void) {
    if (!secure_boot_initialized) return false;
    uint8_t current[SECURE_BOOT_HASH_SIZE];
    hash_kernel_image(current);
    if (bytes_equal(current, kernel_boot_hash, sizeof(current))) return true;
    boot_state = SECURE_BOOT_STATE_COMPROMISED;
    return false;
}

void secure_boot_periodic(void) {
    static uint32_t last_check = 0;
    if (!runtime_monitoring) return;
    uint32_t now = get_system_time();
    if (now - last_check < MONITOR_INTERVAL_MS) return;
    last_check = now;
    if (!secure_boot_check_runtime_integrity()) {
        terminal_set_color(12, 0);
        terminal_write_string("SECURE_BOOT: kernel image changed since boot\n");
        terminal_set_color(7, 0);
    }
}

bool secure_boot_recovery_mode(void) {
    for (uint8_t i = 0; i < PCR_COUNT; i++) secure_boot_pcr_reset(i);
    measurement_count = 0;
    measure_boot_chain();
    return boot_state != SECURE_BOOT_STATE_COMPROMISED;
}

bool secure_boot_update_component(boot_component_type_t type, const void* new_data, uint32_t size) {
    boot_component_t* enrolled = find_component(type, NULL);
    if (!setup_mode || !enrolled || !new_data || size == 0) return false;
    if (!crypto_sha256((const uint8_t*)new_data, size, enrolled->hash)) return false;
    enrolled->size = size;
    if (enrolled->is_signed) {
        enrolled->is_signed = sign_hash(enrolled->hash, enrolled->signature);
        enrolled->signature_size = enrolled->is_signed ? HMAC_SIZE : 0;
    }
    return true;
}

bool secure_boot_backup_measurements(void) {
    copy_bytes(backup.pcrs, pcrs, sizeof(pcrs));
    copy_bytes(backup.measurements, measurements, sizeof(measurements));
    backup.measurement_count = measurement_count;
    backup.valid = true;
    return true;
}

bool secure_boot_restore_measurements(void) {
    if (!backup.valid) return false;
    for (uint8_t i = 0; i < PCR_COUNT; i++) {
        if (pcr_locked[i]) return false;
    }
    copy_bytes(pcrs, backup.pcrs, sizeof(pcrs));
    copy_bytes(measurements, backup.measurements, sizeof(measurements));
    measurement_count = backup.measurement_count;
    return true;
}

static const char* state_name(secure_boot_state_t state) {
    switch (state) {
        case SECURE_BOOT_STATE_UNVERIFIED: return "UNVERIFIED";
        case SECURE_BOOT_STATE_VERIFYING: return "VERIFYING";
        case SECURE_BOOT_STATE_VERIFIED: return "VERIFIED";
        case SECURE_BOOT_STATE_FAILED: return "FAILED";
        case SECURE_BOOT_STATE_COMPROMISED: return "COMPROMISED";
    }
    return "UNKNOWN";
}

void secure_boot_print_status(void) {
    terminal_write_string("\n=== APOLLO SECURE BOOT STATUS ===\n");
    terminal_write_string("Boot State: ");
    terminal_set_color(boot_state == SECURE_BOOT_STATE_VERIFIED ? 10 : (boot_state == SECURE_BOOT_STATE_UNVERIFIED ? 14 : 12), 0);
    terminal_write_string(state_name(boot_state));
    terminal_set_color(7, 0);
    terminal_write_string("\nKernel reference: ");
    terminal_write_string(!kernel_reference_present ? "not embedded" : (kernel_matches_reference ? "match" : "MISMATCH"));
    terminal_write_string("\nPolicy: ");
    terminal_write_string(policy);
    terminal_write_string("  Setup mode: ");
    terminal_write_string(setup_mode ? "yes" : "no");
    terminal_write_string("  Platform key: ");
    terminal_write_string(platform_key_size ? "loaded" : "none");
    terminal_write_string("\nMeasurements: ");
    terminal_write_uint(measurement_count);
    terminal_write_string("  Enrolled components: ");
    terminal_write_uint(component_count);
    terminal_write_string("  Certificates: ");
    terminal_write_uint(certificate_count);
    terminal_write_string("\nRuntime monitoring: ");
    terminal_write_string(runtime_monitoring ? "on" : "off");
    terminal_write_string("\nKernel hash: ");
    write_hash(kernel_boot_hash);
    terminal_write_string("\n");
}

void secure_boot_print_measurements(void) {
    terminal_write_string("\n=== BOOT MEASUREMENTS ===\n");
    if (measurement_count == 0) {
        terminal_write_string("No measurements recorded\n");
    }
    for (uint32_t i = 0; i < measurement_count; i++) {
        const boot_measurement_t* m = &measurements[i];
        terminal_write_string(type_name(m->component_type));
        terminal_write_string(": ");
        terminal_write_string(m->component_name);
        terminal_write_string(" (");
        terminal_write_uint(m->component_size);
        terminal_write_string(" bytes, PCR ");
        terminal_write_uint(pcr_for_type(m->component_type));
        terminal_write_string(")\n  ");
        write_hash(m->measurement);
        terminal_write_string("\n  Status: ");
        if (is_zero(m->expected_hash, SECURE_BOOT_HASH_SIZE)) {
            terminal_write_string("measured, no reference\n");
        } else {
            terminal_set_color(m->is_verified ? 10 : 12, 0);
            terminal_write_string(m->is_verified ? "matches reference\n" : "DOES NOT match reference\n");
            terminal_set_color(7, 0);
        }
    }
}

void secure_boot_print_certificates(void) {
    terminal_write_string("\n=== CERTIFICATES ===\n");
    if (certificate_count == 0) {
        terminal_write_string("No certificates enrolled\n");
    }
    for (uint32_t i = 0; i < certificate_count; i++) {
        const secure_boot_certificate_t* c = &certificates[i];
        terminal_write_string("Serial ");
        terminal_write_uint(c->serial_number);
        terminal_write_string(c->is_ca ? "  CA" : "  leaf");
        terminal_write_string(c->is_revoked ? "  revoked" : "");
        terminal_write_string(secure_boot_verify_certificate_chain(c) ? "  chain valid\n" : "  chain INVALID\n");
        terminal_write_string("  Subject: ");
        write_hash(c->subject_hash);
        terminal_write_string("\n");
    }
}

static bool self_test_report(const char* name, bool ok) {
    terminal_write_string("SECURE_BOOT: ");
    terminal_write_string(name);
    terminal_write_string(ok ? " PASSED\n" : " FAILED\n");
    return ok;
}

// PCR 23 is reserved for this test, an extend must equal SHA256(old || SHA256(data))
static bool test_pcr_extend(void) {
    static const uint8_t data[6] = {'a', 'p', 'o', 'l', 'l', 'o'};
    uint8_t joined[SECURE_BOOT_HASH_SIZE * 2];
    uint8_t expected[SECURE_BOOT_HASH_SIZE];
    uint8_t actual[SECURE_BOOT_HASH_SIZE];
    if (pcr_locked[PCR_SELF_TEST] || !secure_boot_pcr_reset(PCR_SELF_TEST)) return false;
    zero_bytes(joined, SECURE_BOOT_HASH_SIZE);
    crypto_sha256(data, sizeof(data), joined + SECURE_BOOT_HASH_SIZE);
    crypto_sha256(joined, sizeof(joined), expected);
    bool ok = secure_boot_pcr_extend(PCR_SELF_TEST, data, sizeof(data)) &&
              secure_boot_pcr_read(PCR_SELF_TEST, actual) &&
              bytes_equal(expected, actual, SECURE_BOOT_HASH_SIZE);
    secure_boot_pcr_reset(PCR_SELF_TEST);
    return ok;
}

static bool test_signatures(void) {
    static const uint8_t test_key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t saved_key[PLATFORM_KEY_MAX];
    uint32_t saved_size = platform_key_size;
    uint8_t hash[SECURE_BOOT_HASH_SIZE] = {0};
    uint8_t signature[HMAC_SIZE];
    copy_bytes(saved_key, platform_key, PLATFORM_KEY_MAX);
    copy_bytes(platform_key, test_key, sizeof(test_key));
    platform_key_size = sizeof(test_key);

    bool signed_ok = sign_hash(hash, signature) && signature_valid(hash, signature);
    hash[0] ^= 1;
    bool tamper_caught = !signature_valid(hash, signature);

    copy_bytes(platform_key, saved_key, PLATFORM_KEY_MAX);
    platform_key_size = saved_size;
    zero_bytes(saved_key, sizeof(saved_key));
    return signed_ok && tamper_caught;
}

bool secure_boot_self_test(void) {
    if (!secure_boot_initialized) return false;
    bool ok = self_test_report("PCR extend", test_pcr_extend());
    ok &= self_test_report("HMAC sign and tamper check", test_signatures());
    ok &= self_test_report("Kernel image unchanged since boot", secure_boot_check_runtime_integrity());
    if (kernel_reference_present) {
        ok &= self_test_report("Kernel matches build reference", kernel_matches_reference);
    } else {
        terminal_write_string("SECURE_BOOT: no build reference embedded, kernel check skipped\n");
    }
    return ok;
}
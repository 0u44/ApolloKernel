#ifndef APOLLO_SECURE_BOOT_H
#define APOLLO_SECURE_BOOT_H

#include "types.h"

#define SECURE_BOOT_MAX_CERTS 16
#define SECURE_BOOT_MAX_MEASUREMENTS 32
#define SECURE_BOOT_SIGNATURE_SIZE 256
#define SECURE_BOOT_HASH_SIZE 32
#define SECURE_BOOT_MAX_COMPONENTS 64

typedef enum {
    SECURE_BOOT_STATE_UNVERIFIED = 0,
    SECURE_BOOT_STATE_VERIFYING = 1,
    SECURE_BOOT_STATE_VERIFIED = 2,
    SECURE_BOOT_STATE_FAILED = 3,
    SECURE_BOOT_STATE_COMPROMISED = 4
} secure_boot_state_t;

typedef enum {
    BOOT_COMPONENT_FIRMWARE = 0,
    BOOT_COMPONENT_BOOTLOADER = 1,
    BOOT_COMPONENT_KERNEL = 2,
    BOOT_COMPONENT_INITRD = 3,
    BOOT_COMPONENT_DRIVER = 4,
    BOOT_COMPONENT_CONFIG = 5,
    BOOT_COMPONENT_APPLICATION = 6
} boot_component_type_t;

typedef struct {
    uint8_t public_key[512];  // RSA public key
    uint16_t key_size;
    uint8_t signature[SECURE_BOOT_SIGNATURE_SIZE];
    uint8_t subject_hash[SECURE_BOOT_HASH_SIZE];
    uint8_t issuer_hash[SECURE_BOOT_HASH_SIZE];
    uint32_t serial_number;
    uint32_t valid_from;
    uint32_t valid_until;
    bool is_ca;
    bool is_revoked;
    bool is_trusted;
} secure_boot_certificate_t;

typedef struct {
    boot_component_type_t component_type;
    char component_name[64];
    uint8_t measurement[SECURE_BOOT_HASH_SIZE];
    uint8_t expected_hash[SECURE_BOOT_HASH_SIZE];
    uint32_t component_size;
    uint32_t load_address;
    uint32_t measurement_time;
    bool is_verified;
    bool is_critical;
} boot_measurement_t;

typedef struct {
    boot_component_type_t type;
    char name[64];
    char version[32];
    uint8_t* data;
    uint32_t size;
    uint8_t hash[SECURE_BOOT_HASH_SIZE];
    uint8_t signature[SECURE_BOOT_SIGNATURE_SIZE];
    uint32_t signature_size;
    secure_boot_certificate_t* cert;
    bool is_signed;
    bool is_verified;
    bool is_trusted;
} boot_component_t;

typedef struct {
    uint8_t platform_pcrs[24][SECURE_BOOT_HASH_SIZE];
    uint8_t boot_measurements[SECURE_BOOT_MAX_MEASUREMENTS][SECURE_BOOT_HASH_SIZE];
    uint32_t measurement_count;
    
    secure_boot_state_t boot_state;
    uint32_t boot_time;
    uint32_t report_time;
    
    uint8_t attestation_signature[SECURE_BOOT_SIGNATURE_SIZE];
    uint32_t signature_size;
    
    char platform_info[128];
    char boot_policy[256];
} secure_boot_attestation_t;

bool secure_boot_initialize(void);
bool secure_boot_early_init(void);
void secure_boot_shutdown(void);
bool secure_boot_load_platform_key(const uint8_t* key_data, uint32_t key_size);
bool secure_boot_add_certificate(const secure_boot_certificate_t* cert);
bool secure_boot_revoke_certificate(const uint8_t* cert_hash);
bool secure_boot_verify_certificate_chain(const secure_boot_certificate_t* cert);
bool secure_boot_verify_component(boot_component_t* component);
bool secure_boot_add_component(const boot_component_t* component);
bool secure_boot_measure_component(boot_component_type_t type, const char* name, 
                                  const void* data, uint32_t size);
bool secure_boot_pcr_extend(uint8_t pcr_index, const uint8_t* data, uint32_t data_size);
bool secure_boot_pcr_read(uint8_t pcr_index, uint8_t* pcr_value);
bool secure_boot_pcr_reset(uint8_t pcr_index);
void secure_boot_pcr_lock(uint8_t pcr_index);
bool secure_boot_verify_bootloader(const void* bootloader_data, uint32_t size);
bool secure_boot_verify_kernel(const void* kernel_data, uint32_t size);
bool secure_boot_verify_drivers(void);
secure_boot_state_t secure_boot_get_state(void);
bool secure_boot_set_policy(const char* policy);
bool secure_boot_check_policy_compliance(void);
bool secure_boot_enter_setup_mode(void);
bool secure_boot_exit_setup_mode(void);
bool secure_boot_generate_attestation(secure_boot_attestation_t* attestation);
bool secure_boot_verify_attestation(const secure_boot_attestation_t* attestation);
bool secure_boot_remote_attestation(const char* nonce, uint8_t* attestation_data, uint32_t* data_size);
bool secure_boot_start_runtime_monitoring(void);
void secure_boot_stop_runtime_monitoring(void);
bool secure_boot_check_runtime_integrity(void);
bool secure_boot_recovery_mode(void);
bool secure_boot_update_component(boot_component_type_t type, const void* new_data, uint32_t size);
bool secure_boot_backup_measurements(void);
bool secure_boot_restore_measurements(void);
void secure_boot_print_status(void);
void secure_boot_print_measurements(void);
void secure_boot_print_certificates(void);
bool secure_boot_self_test(void);
const char* secure_boot_get_policy(void);
bool secure_boot_in_setup_mode(void);
void secure_boot_periodic(void);

#endif
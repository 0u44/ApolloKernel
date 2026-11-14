#ifndef APOLLO_CRYPTO_H
#define APOLLO_CRYPTO_H

#include "types.h"

#define CRYPTO_AES_BLOCK_SIZE 16
#define CRYPTO_AES_KEY_SIZE_128 16
#define CRYPTO_AES_KEY_SIZE_192 24
#define CRYPTO_AES_KEY_SIZE_256 32

#define CRYPTO_SHA256_DIGEST_SIZE 32
#define CRYPTO_SHA512_DIGEST_SIZE 64
#define CRYPTO_SHA256_BLOCK_SIZE 64
#define CRYPTO_SHA512_BLOCK_SIZE 128

#define CRYPTO_HMAC_MAX_KEY_SIZE 128

#define CRYPTO_ENTROPY_POOL_SIZE 512
#define CRYPTO_MIN_ENTROPY_BITS 256

#define CRYPTO_CONTEXT_MAGIC 0x43525950  // "CRYP"
#define CRYPTO_KEY_MAGIC 0x4B455900      // "KEY\0"

typedef enum {
    CRYPTO_CIPHER_AES_128_ECB = 0,  // ECB leaks repeated blocks, use CBC or CTR
    CRYPTO_CIPHER_AES_128_CBC = 1,
    CRYPTO_CIPHER_AES_128_CTR = 2,
    CRYPTO_CIPHER_AES_256_ECB = 3,  // ECB leaks repeated blocks, use CBC or CTR
    CRYPTO_CIPHER_AES_256_CBC = 4,
    CRYPTO_CIPHER_AES_256_CTR = 5
} crypto_cipher_t;

typedef enum {
    CRYPTO_HASH_SHA256 = 0,
    CRYPTO_HASH_SHA512 = 1
} crypto_hash_t;

typedef enum {
    CRYPTO_ENTROPY_RDRAND = 0x01,
    CRYPTO_ENTROPY_RDSEED = 0x02,
    CRYPTO_ENTROPY_JITTER = 0x04,
    CRYPTO_ENTROPY_INTERRUPT = 0x08,
    CRYPTO_ENTROPY_MEMORY = 0x10
} crypto_entropy_source_t;

typedef struct {
    uint32_t magic;
    uint32_t guard_pre[4];
    
    uint32_t round_keys[60];           // Room for AES-256, which uses 60 words
    uint8_t key_size;
    uint8_t num_rounds;
    uint8_t iv[CRYPTO_AES_BLOCK_SIZE];
    uint8_t counter[CRYPTO_AES_BLOCK_SIZE]; // For CTR mode
    
    uint32_t guard_post[4];
    uint32_t checksum;
} crypto_aes_context_t;

typedef struct {
    uint32_t magic;
    uint32_t guard_pre[4];
    
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[CRYPTO_SHA256_BLOCK_SIZE];
    
    uint32_t guard_post[4];
    uint32_t checksum;
} crypto_sha256_context_t;

typedef struct {
    uint32_t magic;
    uint32_t guard_pre[4];
    
    uint64_t state[8];
    uint64_t count;
    uint8_t buffer[CRYPTO_SHA512_BLOCK_SIZE];
    
    uint32_t guard_post[4];
    uint32_t checksum;
} crypto_sha512_context_t;

typedef struct {
    uint32_t magic;
    uint32_t guard_pre[4];
    
    crypto_hash_t hash_type;
    union {
        crypto_sha256_context_t sha256;
        crypto_sha512_context_t sha512;
    } hash_ctx;
    uint8_t key_pad[CRYPTO_SHA512_BLOCK_SIZE];
    uint8_t digest_size;
    
    uint32_t guard_post[4];
    uint32_t checksum;
} crypto_hmac_context_t;

typedef struct {
    uint32_t available_entropy_bits;
    uint32_t total_entropy_collected;
    uint8_t active_sources;
    uint32_t rdrand_successes;
    uint32_t rdrand_failures;
    uint32_t rdseed_successes;
    uint32_t rdseed_failures;
    uint32_t last_reseed_time;
} crypto_entropy_stats_t;

bool crypto_initialize(void);
void crypto_shutdown(void);
bool crypto_self_test(void);

bool crypto_detect_entropy_sources(void);

uint8_t crypto_get_entropy_sources(void);

bool crypto_add_entropy_rdrand(void);
bool crypto_add_entropy_rdseed(void);
bool crypto_add_entropy_jitter(void);
bool crypto_add_entropy_interrupt(uint64_t timestamp);
bool crypto_add_entropy_manual(const uint8_t* data, uint32_t size);

bool crypto_get_entropy_stats(crypto_entropy_stats_t* stats);

bool crypto_wait_for_entropy(uint32_t required_bits, uint32_t timeout_ms);

bool crypto_rng_get_bytes(uint8_t* buffer, uint32_t size);

bool crypto_rng_get_bytes_nonblock(uint8_t* buffer, uint32_t size);

uint32_t crypto_rng_get_uint32(void);

uint64_t crypto_rng_get_uint64(void);

bool crypto_aes_init(crypto_aes_context_t* ctx, crypto_cipher_t cipher, 
                    const uint8_t* key, const uint8_t* iv);

bool crypto_aes_encrypt_block(crypto_aes_context_t* ctx, const uint8_t* input, uint8_t* output);

bool crypto_aes_decrypt_block(crypto_aes_context_t* ctx, const uint8_t* input, uint8_t* output);

bool crypto_aes_encrypt(crypto_aes_context_t* ctx, const uint8_t* input, 
                       uint8_t* output, uint32_t length);

bool crypto_aes_decrypt(crypto_aes_context_t* ctx, const uint8_t* input, 
                       uint8_t* output, uint32_t length);

void crypto_aes_destroy(crypto_aes_context_t* ctx);

bool crypto_sha256_init(crypto_sha256_context_t* ctx);
void crypto_sha256_update(crypto_sha256_context_t* ctx, const uint8_t* data, uint32_t length);
void crypto_sha256_final(crypto_sha256_context_t* ctx, uint8_t* digest);
void crypto_sha256_destroy(crypto_sha256_context_t* ctx);

bool crypto_sha256(const uint8_t* data, uint32_t length, uint8_t* digest);

bool crypto_sha512_init(crypto_sha512_context_t* ctx);
void crypto_sha512_update(crypto_sha512_context_t* ctx, const uint8_t* data, uint32_t length);
void crypto_sha512_final(crypto_sha512_context_t* ctx, uint8_t* digest);
void crypto_sha512_destroy(crypto_sha512_context_t* ctx);

bool crypto_sha512(const uint8_t* data, uint32_t length, uint8_t* digest);

bool crypto_hmac_init(crypto_hmac_context_t* ctx, crypto_hash_t hash_type, 
                     const uint8_t* key, uint32_t key_size);
void crypto_hmac_update(crypto_hmac_context_t* ctx, const uint8_t* data, uint32_t length);
void crypto_hmac_final(crypto_hmac_context_t* ctx, uint8_t* mac);
void crypto_hmac_destroy(crypto_hmac_context_t* ctx);

bool crypto_hmac(crypto_hash_t hash_type, const uint8_t* key, uint32_t key_size,
                const uint8_t* data, uint32_t data_size, uint8_t* mac);

bool crypto_secure_compare(const uint8_t* a, const uint8_t* b, uint32_t length);

void crypto_secure_zero(void* ptr, uint32_t size);

uint32_t crypto_padding_pkcs7_add(uint8_t* buffer, uint32_t data_size, 
                                 uint32_t buffer_size, uint8_t block_size);
bool crypto_padding_pkcs7_remove(uint8_t* buffer, uint32_t* data_size, uint8_t block_size);

bool crypto_validate_aes_context(const crypto_aes_context_t* ctx);
bool crypto_validate_sha256_context(const crypto_sha256_context_t* ctx);
bool crypto_validate_sha512_context(const crypto_sha512_context_t* ctx);
bool crypto_validate_hmac_context(const crypto_hmac_context_t* ctx);

#endif
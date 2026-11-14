#include "crypto.h"
#include "heap_allocator.h"
#include "terminal.h"
#include "string_utils.h"
#include "time_keeper.h"

static bool crypto_initialized = false;
static uint8_t crypto_entropy_sources = 0;

// Entropy pool, should be in locked memory
static struct {
    uint8_t pool[CRYPTO_ENTROPY_POOL_SIZE];
    uint32_t write_pos;
    uint32_t read_pos;
    uint32_t available_bits;
    uint64_t reseed_counter;
    crypto_entropy_stats_t stats;
} entropy_state;

static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t aes_inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static uint32_t calculate_checksum(const void* data, uint32_t size) {
    uint32_t sum = 0;
    const uint8_t* bytes = (const uint8_t*)data;
    for (uint32_t i = 0; i < size; i++) {
        sum += bytes[i];
        sum = (sum << 1) | (sum >> 31);
    }
    return sum;
}

static void init_context_guards(uint32_t* pre, uint32_t* post, uint32_t magic) {
    pre[0] = magic;
    pre[1] = ~magic;
    pre[2] = magic ^ 0xAAAAAAAA;
    pre[3] = magic ^ 0x55555555;
    
    post[0] = magic;
    post[1] = ~magic;
    post[2] = magic ^ 0xAAAAAAAA;
    post[3] = magic ^ 0x55555555;
}

static bool check_context_guards(const uint32_t* pre, const uint32_t* post, uint32_t magic) {
    return (pre[0] == magic && pre[1] == ~magic && 
            pre[2] == (magic ^ 0xAAAAAAAA) && pre[3] == (magic ^ 0x55555555) &&
            post[0] == magic && post[1] == ~magic &&
            post[2] == (magic ^ 0xAAAAAAAA) && post[3] == (magic ^ 0x55555555));
}

// Entropy sources

static bool try_rdrand(uint64_t* value) {
    uint8_t success = 0;
    __asm__ volatile(
        "rdrand %0\n\t"
        "setc %1"
        : "=r"(*value), "=qm"(success)
        :
        : "cc"
    );
    return success != 0;
}

static bool try_rdseed(uint64_t* value) {
    uint8_t success = 0;
    __asm__ volatile(
        "rdseed %0\n\t"
        "setc %1"
        : "=r"(*value), "=qm"(success)
        :
        : "cc"
    );
    return success != 0;
}

static uint64_t get_jitter_entropy(void) {
    uint64_t jitter = 0;
    
    // Use RDTSC (timestamp counter) variations
    for (int i = 0; i < 100; i++) {
        uint32_t lo, hi;
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        jitter ^= ((uint64_t)hi << 32) | lo;
        
        volatile uint8_t* ptr = (volatile uint8_t*)&jitter;
        jitter += *ptr;
    }
    
    return jitter;
}

static bool cpu_has_rdrand(void) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1), "c"(0)
    );
    return (ecx & (1 << 30)) != 0;
}

static bool cpu_has_rdseed(void) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(7), "c"(0)
    );
    return (ebx & (1 << 18)) != 0;
}

bool crypto_detect_entropy_sources(void) {
    crypto_entropy_sources = 0;
    
    if (cpu_has_rdrand()) {
        crypto_entropy_sources |= CRYPTO_ENTROPY_RDRAND;
        terminal_write_string("CRYPTO: RDRAND available\n");
    }
    
    if (cpu_has_rdseed()) {
        crypto_entropy_sources |= CRYPTO_ENTROPY_RDSEED;
        terminal_write_string("CRYPTO: RDSEED available\n");
    }
    
    // Always available fallbacks
    crypto_entropy_sources |= CRYPTO_ENTROPY_JITTER;
    crypto_entropy_sources |= CRYPTO_ENTROPY_INTERRUPT;
    crypto_entropy_sources |= CRYPTO_ENTROPY_MEMORY;
    
    terminal_write_string("CRYPTO: Jitter/Interrupt/Memory entropy available\n");
    
    return crypto_entropy_sources != 0;
}

uint8_t crypto_get_entropy_sources(void) {
    return crypto_entropy_sources;
}

bool crypto_add_entropy_rdrand(void) {
    if (!(crypto_entropy_sources & CRYPTO_ENTROPY_RDRAND)) {
        return false;
    }
    
    uint64_t value;
    for (int attempt = 0; attempt < 10; attempt++) {
        if (try_rdrand(&value)) {
            entropy_state.stats.rdrand_successes++;
            
            // Mix into pool using XOR
            for (uint32_t i = 0; i < sizeof(value); i++) {
                uint32_t pos = (entropy_state.write_pos + i) % CRYPTO_ENTROPY_POOL_SIZE;
                entropy_state.pool[pos] ^= ((uint8_t*)&value)[i];
            }
            entropy_state.write_pos = (entropy_state.write_pos + sizeof(value)) % CRYPTO_ENTROPY_POOL_SIZE;
            entropy_state.available_bits += 64;
            if (entropy_state.available_bits > CRYPTO_ENTROPY_POOL_SIZE * 8) {
                entropy_state.available_bits = CRYPTO_ENTROPY_POOL_SIZE * 8;
            }
            entropy_state.stats.total_entropy_collected += 64;
            return true;
        }
    }
    
    entropy_state.stats.rdrand_failures++;
    return false;
}

bool crypto_add_entropy_rdseed(void) {
    if (!(crypto_entropy_sources & CRYPTO_ENTROPY_RDSEED)) {
        return false;
    }
    
    uint64_t value;
    for (int attempt = 0; attempt < 10; attempt++) {
        if (try_rdseed(&value)) {
            entropy_state.stats.rdseed_successes++;
            
            for (uint32_t i = 0; i < sizeof(value); i++) {
                uint32_t pos = (entropy_state.write_pos + i) % CRYPTO_ENTROPY_POOL_SIZE;
                entropy_state.pool[pos] ^= ((uint8_t*)&value)[i];
            }
            entropy_state.write_pos = (entropy_state.write_pos + sizeof(value)) % CRYPTO_ENTROPY_POOL_SIZE;
            entropy_state.available_bits += 64;
            if (entropy_state.available_bits > CRYPTO_ENTROPY_POOL_SIZE * 8) {
                entropy_state.available_bits = CRYPTO_ENTROPY_POOL_SIZE * 8;
            }
            entropy_state.stats.total_entropy_collected += 64;
            return true;
        }
    }
    
    entropy_state.stats.rdseed_failures++;
    return false;
}

bool crypto_add_entropy_jitter(void) {
    uint64_t jitter = get_jitter_entropy();
    
    for (uint32_t i = 0; i < sizeof(jitter); i++) {
        uint32_t pos = (entropy_state.write_pos + i) % CRYPTO_ENTROPY_POOL_SIZE;
        entropy_state.pool[pos] ^= ((uint8_t*)&jitter)[i];
    }
    entropy_state.write_pos = (entropy_state.write_pos + sizeof(jitter)) % CRYPTO_ENTROPY_POOL_SIZE;
    
    // Jitter entropy is lower quality, credit fewer bits
    entropy_state.available_bits += 16;
    if (entropy_state.available_bits > CRYPTO_ENTROPY_POOL_SIZE * 8) {
        entropy_state.available_bits = CRYPTO_ENTROPY_POOL_SIZE * 8;
    }
    entropy_state.stats.total_entropy_collected += 16;
    return true;
}

bool crypto_add_entropy_interrupt(uint64_t timestamp) {
    for (uint32_t i = 0; i < sizeof(timestamp); i++) {
        uint32_t pos = (entropy_state.write_pos + i) % CRYPTO_ENTROPY_POOL_SIZE;
        entropy_state.pool[pos] ^= ((uint8_t*)&timestamp)[i];
    }
    entropy_state.write_pos = (entropy_state.write_pos + sizeof(timestamp)) % CRYPTO_ENTROPY_POOL_SIZE;
    
    // Interrupt timing is low quality, credit few bits
    entropy_state.available_bits += 4;
    if (entropy_state.available_bits > CRYPTO_ENTROPY_POOL_SIZE * 8) {
        entropy_state.available_bits = CRYPTO_ENTROPY_POOL_SIZE * 8;
    }
    entropy_state.stats.total_entropy_collected += 4;
    return true;
}

bool crypto_add_entropy_manual(const uint8_t* data, uint32_t size) {
    if (!data || size == 0) return false;
    
    for (uint32_t i = 0; i < size; i++) {
        uint32_t pos = (entropy_state.write_pos + i) % CRYPTO_ENTROPY_POOL_SIZE;
        entropy_state.pool[pos] ^= data[i];
    }
    entropy_state.write_pos = (entropy_state.write_pos + size) % CRYPTO_ENTROPY_POOL_SIZE;
    
    // Manual entropy quality unknown, credit conservatively
    uint32_t bits = (size * 8) / 4;
    entropy_state.available_bits += bits;
    if (entropy_state.available_bits > CRYPTO_ENTROPY_POOL_SIZE * 8) {
        entropy_state.available_bits = CRYPTO_ENTROPY_POOL_SIZE * 8;
    }
    entropy_state.stats.total_entropy_collected += bits;
    return true;
}

bool crypto_get_entropy_stats(crypto_entropy_stats_t* stats) {
    if (!stats) return false;
    
    stats->available_entropy_bits = entropy_state.available_bits;
    stats->total_entropy_collected = entropy_state.stats.total_entropy_collected;
    stats->active_sources = crypto_entropy_sources;
    stats->rdrand_successes = entropy_state.stats.rdrand_successes;
    stats->rdrand_failures = entropy_state.stats.rdrand_failures;
    stats->rdseed_successes = entropy_state.stats.rdseed_successes;
    stats->rdseed_failures = entropy_state.stats.rdseed_failures;
    stats->last_reseed_time = entropy_state.stats.last_reseed_time;
    
    return true;
}

bool crypto_wait_for_entropy(uint32_t required_bits, uint32_t timeout_ms) {
    uint32_t start_time = (uint32_t)time_keeper_get_uptime_seconds() * 1000;
    
    while (entropy_state.available_bits < required_bits) {
        if (crypto_entropy_sources & CRYPTO_ENTROPY_RDRAND) {
            crypto_add_entropy_rdrand();
        }
        if (crypto_entropy_sources & CRYPTO_ENTROPY_RDSEED) {
            crypto_add_entropy_rdseed();
        }
        crypto_add_entropy_jitter();
        
        uint32_t current_time = (uint32_t)time_keeper_get_uptime_seconds() * 1000;
        if (timeout_ms > 0 && (current_time - start_time) > timeout_ms) {
            return false;
        }
        
        // Small delay to avoid busy loop
        for (volatile int i = 0; i < 1000; i++);
    }
    
    return true;
}

// Random numbers

bool crypto_rng_get_bytes(uint8_t* buffer, uint32_t size) {
    if (!crypto_initialized || !buffer || size == 0) {
        return false;
    }
    
    if (!crypto_wait_for_entropy(size * 8, 5000)) {
        terminal_write_string("CRYPTO: ERROR - Insufficient entropy\n");
        return false;
    }
    
    for (uint32_t i = 0; i < size; i++) {
        buffer[i] = entropy_state.pool[entropy_state.read_pos];
        entropy_state.read_pos = (entropy_state.read_pos + 1) % CRYPTO_ENTROPY_POOL_SIZE;
        
        if (entropy_state.available_bits >= 8) {
            entropy_state.available_bits -= 8;
        }
    }
    
    // Reseed pool after extraction
    entropy_state.reseed_counter++;
    if (entropy_state.reseed_counter % 16 == 0) {
        crypto_add_entropy_rdrand();
        crypto_add_entropy_rdseed();
        crypto_add_entropy_jitter();
        entropy_state.stats.last_reseed_time = (uint32_t)time_keeper_get_uptime_seconds();
    }
    
    return true;
}

bool crypto_rng_get_bytes_nonblock(uint8_t* buffer, uint32_t size) {
    if (!crypto_initialized || !buffer || size == 0) {
        return false;
    }
    
    if (entropy_state.available_bits < size * 8) {
        return false;
    }
    
    return crypto_rng_get_bytes(buffer, size);
}

uint32_t crypto_rng_get_uint32(void) {
    uint32_t value = 0;
    crypto_rng_get_bytes((uint8_t*)&value, sizeof(value));
    return value;
}

uint64_t crypto_rng_get_uint64(void) {
    uint64_t value = 0;
    crypto_rng_get_bytes((uint8_t*)&value, sizeof(value));
    return value;
}

// AES

#define AES_RCON_FIRST 0x01
#define AES_REDUCTION_POLY 0x1B
#define AES_NK_256_SUBWORD 4

static uint32_t aes_sub_word(uint32_t word) {
    return ((uint32_t)aes_sbox[(word >> 24) & 0xFF] << 24) |
           ((uint32_t)aes_sbox[(word >> 16) & 0xFF] << 16) |
           ((uint32_t)aes_sbox[(word >> 8) & 0xFF] << 8) |
           ((uint32_t)aes_sbox[word & 0xFF]);
}

static uint32_t gf_double(uint32_t value) {
    value <<= 1;
    if (value & 0x100) value ^= 0x100 | AES_REDUCTION_POLY;
    return value;
}

static void aes_key_expansion(crypto_aes_context_t* ctx, const uint8_t* key, uint8_t key_size) {
    uint32_t nk = key_size / 4;  // Number of 32-bit words in key
    uint32_t nr = (key_size == 16) ? 10 : (key_size == 24) ? 12 : 14;
    
    ctx->num_rounds = nr;
    ctx->key_size = key_size;
    
    for (uint32_t i = 0; i < nk; i++) {
        ctx->round_keys[i] = ((uint32_t)key[4*i] << 24) |
                             ((uint32_t)key[4*i+1] << 16) |
                             ((uint32_t)key[4*i+2] << 8) |
                             ((uint32_t)key[4*i+3]);
    }
    
    uint32_t rcon = AES_RCON_FIRST;
    for (uint32_t i = nk; i < 4 * (nr + 1); i++) {
        uint32_t temp = ctx->round_keys[i-1];

        if (i % nk == 0) {
            temp = aes_sub_word((temp << 8) | (temp >> 24)) ^ (rcon << 24);
            rcon = gf_double(rcon);
        } else if (nk > AES_NK_256_SUBWORD && i % nk == AES_NK_256_SUBWORD) {
            // AES-256 runs SubWord on the middle word of each eight word group
            temp = aes_sub_word(temp);
        }

        ctx->round_keys[i] = ctx->round_keys[i-nk] ^ temp;
    }
}

static void aes_sub_bytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = aes_sbox[state[i]];
    }
}

static void aes_inv_sub_bytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = aes_inv_sbox[state[i]];
    }
}

static void aes_shift_rows(uint8_t* state) {
    uint8_t temp;
    
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

static void aes_inv_shift_rows(uint8_t* state) {
    uint8_t temp;
    
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        // Constant-time: always perform operations
        uint8_t mask = -(b & 1);
        p ^= (a & mask);
        
        uint8_t hi_bit_set = -(a >> 7);
        a <<= 1;
        a ^= (0x1B & hi_bit_set);
        b >>= 1;
    }
    return p;
}

static void aes_mix_columns(uint8_t* state) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i*4];
        uint8_t s1 = state[i*4 + 1];
        uint8_t s2 = state[i*4 + 2];
        uint8_t s3 = state[i*4 + 3];
        
        state[i*4] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3;
        state[i*4 + 1] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
        state[i*4 + 2] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
        state[i*4 + 3] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2);
    }
}

static void aes_inv_mix_columns(uint8_t* state) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i*4];
        uint8_t s1 = state[i*4 + 1];
        uint8_t s2 = state[i*4 + 2];
        uint8_t s3 = state[i*4 + 3];
        
        state[i*4] = gf_mul(s0, 14) ^ gf_mul(s1, 11) ^ gf_mul(s2, 13) ^ gf_mul(s3, 9);
        state[i*4 + 1] = gf_mul(s0, 9) ^ gf_mul(s1, 14) ^ gf_mul(s2, 11) ^ gf_mul(s3, 13);
        state[i*4 + 2] = gf_mul(s0, 13) ^ gf_mul(s1, 9) ^ gf_mul(s2, 14) ^ gf_mul(s3, 11);
        state[i*4 + 3] = gf_mul(s0, 11) ^ gf_mul(s1, 13) ^ gf_mul(s2, 9) ^ gf_mul(s3, 14);
    }
}

static void aes_add_round_key(uint8_t* state, const uint32_t* round_key) {
    for (int i = 0; i < 4; i++) {
        state[i*4] ^= (round_key[i] >> 24) & 0xFF;
        state[i*4 + 1] ^= (round_key[i] >> 16) & 0xFF;
        state[i*4 + 2] ^= (round_key[i] >> 8) & 0xFF;
        state[i*4 + 3] ^= round_key[i] & 0xFF;
    }
}

bool crypto_aes_init(crypto_aes_context_t* ctx, crypto_cipher_t cipher, 
                    const uint8_t* key, const uint8_t* iv) {
    if (!crypto_initialized || !ctx || !key) {
        return false;
    }
    
    uint8_t key_size = 0;
    switch (cipher) {
        case CRYPTO_CIPHER_AES_128_ECB:
        case CRYPTO_CIPHER_AES_128_CBC:
        case CRYPTO_CIPHER_AES_128_CTR:
            key_size = 16;
            break;
        case CRYPTO_CIPHER_AES_256_ECB:
        case CRYPTO_CIPHER_AES_256_CBC:
        case CRYPTO_CIPHER_AES_256_CTR:
            key_size = 32;
            break;
        default:
            return false;
    }
    
    crypto_secure_zero(ctx, sizeof(*ctx));
    ctx->magic = CRYPTO_CONTEXT_MAGIC;
    init_context_guards(ctx->guard_pre, ctx->guard_post, CRYPTO_CONTEXT_MAGIC);
    
    aes_key_expansion(ctx, key, key_size);
    
    if (iv) {
        for (int i = 0; i < CRYPTO_AES_BLOCK_SIZE; i++) {
            ctx->iv[i] = iv[i];
            ctx->counter[i] = iv[i];
        }
    }
    
    ctx->checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
    
    return true;
}

bool crypto_aes_encrypt_block(crypto_aes_context_t* ctx, const uint8_t* input, uint8_t* output) {
    if (!crypto_validate_aes_context(ctx) || !input || !output) {
        return false;
    }
    
    uint8_t state[16];
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];
    }
    
    aes_add_round_key(state, &ctx->round_keys[0]);
    
    for (uint8_t round = 1; round < ctx->num_rounds; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, &ctx->round_keys[round * 4]);
    }
    
    // Final round (no MixColumns)
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, &ctx->round_keys[ctx->num_rounds * 4]);
    
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }
    
    // Clear sensitive data
    crypto_secure_zero(state, sizeof(state));
    
    return true;
}

bool crypto_aes_decrypt_block(crypto_aes_context_t* ctx, const uint8_t* input, uint8_t* output) {
    if (!crypto_validate_aes_context(ctx) || !input || !output) {
        return false;
    }
    
    uint8_t state[16];
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];
    }
    
    aes_add_round_key(state, &ctx->round_keys[ctx->num_rounds * 4]);
    
    for (int round = ctx->num_rounds - 1; round > 0; round--) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, &ctx->round_keys[round * 4]);
        aes_inv_mix_columns(state);
    }
    
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, &ctx->round_keys[0]);
    
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }
    
    crypto_secure_zero(state, sizeof(state));
    
    return true;
}

bool crypto_aes_encrypt(crypto_aes_context_t* ctx, const uint8_t* input, 
                       uint8_t* output, uint32_t length) {
    if (!crypto_validate_aes_context(ctx) || !input || !output) {
        return false;
    }
    
    if (length % CRYPTO_AES_BLOCK_SIZE != 0) {
        return false;  // Data must be block-aligned
    }
    
    uint32_t num_blocks = length / CRYPTO_AES_BLOCK_SIZE;
    
    for (uint32_t i = 0; i < num_blocks; i++) {
        const uint8_t* in_block = input + (i * CRYPTO_AES_BLOCK_SIZE);
        uint8_t* out_block = output + (i * CRYPTO_AES_BLOCK_SIZE);
        
        // CBC mode: XOR with IV/previous ciphertext
        uint8_t temp[CRYPTO_AES_BLOCK_SIZE];
        for (int j = 0; j < CRYPTO_AES_BLOCK_SIZE; j++) {
            temp[j] = in_block[j] ^ ctx->iv[j];
        }
        
        if (!crypto_aes_encrypt_block(ctx, temp, out_block)) {
            crypto_secure_zero(temp, sizeof(temp));
            return false;
        }
        
        for (int j = 0; j < CRYPTO_AES_BLOCK_SIZE; j++) {
            ctx->iv[j] = out_block[j];
        }
        
        crypto_secure_zero(temp, sizeof(temp));
    }
    
    return true;
}

bool crypto_aes_decrypt(crypto_aes_context_t* ctx, const uint8_t* input, 
                       uint8_t* output, uint32_t length) {
    if (!crypto_validate_aes_context(ctx) || !input || !output) {
        return false;
    }
    
    if (length % CRYPTO_AES_BLOCK_SIZE != 0) {
        return false;
    }
    
    uint32_t num_blocks = length / CRYPTO_AES_BLOCK_SIZE;
    
    for (uint32_t i = 0; i < num_blocks; i++) {
        const uint8_t* in_block = input + (i * CRYPTO_AES_BLOCK_SIZE);
        uint8_t* out_block = output + (i * CRYPTO_AES_BLOCK_SIZE);
        
        uint8_t temp[CRYPTO_AES_BLOCK_SIZE];
        
        uint8_t next_iv[CRYPTO_AES_BLOCK_SIZE];
        for (int j = 0; j < CRYPTO_AES_BLOCK_SIZE; j++) {
            next_iv[j] = in_block[j];
        }
        
        if (!crypto_aes_decrypt_block(ctx, in_block, temp)) {
            crypto_secure_zero(temp, sizeof(temp));
            crypto_secure_zero(next_iv, sizeof(next_iv));
            return false;
        }
        
        for (int j = 0; j < CRYPTO_AES_BLOCK_SIZE; j++) {
            out_block[j] = temp[j] ^ ctx->iv[j];
            ctx->iv[j] = next_iv[j];
        }
        
        crypto_secure_zero(temp, sizeof(temp));
        crypto_secure_zero(next_iv, sizeof(next_iv));
    }
    
    return true;
}

void crypto_aes_destroy(crypto_aes_context_t* ctx) {
    if (ctx) {
        crypto_secure_zero(ctx, sizeof(*ctx));
    }
}

// SHA-256

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA256_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x, 2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22))
#define SHA256_EP1(x) (SHA256_ROTR(x, 6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25))
#define SHA256_SIG0(x) (SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform(crypto_sha256_context_t* ctx) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)ctx->buffer[i*4] << 24) |
               ((uint32_t)ctx->buffer[i*4 + 1] << 16) |
               ((uint32_t)ctx->buffer[i*4 + 2] << 8) |
               ((uint32_t)ctx->buffer[i*4 + 3]);
    }
    
    for (int i = 16; i < 64; i++) {
        w[i] = SHA256_SIG1(w[i-2]) + w[i-7] + SHA256_SIG0(w[i-15]) + w[i-16];
    }
    
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    
    for (int i = 0; i < 64; i++) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e, f, g) + sha256_k[i] + w[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
    
    // Clear sensitive data
    crypto_secure_zero(w, sizeof(w));
}

bool crypto_sha256_init(crypto_sha256_context_t* ctx) {
    if (!crypto_initialized || !ctx) return false;
    
    crypto_secure_zero(ctx, sizeof(*ctx));
    ctx->magic = CRYPTO_CONTEXT_MAGIC;
    init_context_guards(ctx->guard_pre, ctx->guard_post, CRYPTO_CONTEXT_MAGIC);
    
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    
    ctx->checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
    return true;
}

void crypto_sha256_update(crypto_sha256_context_t* ctx, const uint8_t* data, uint32_t length) {
    if (!crypto_validate_sha256_context(ctx) || !data) return;
    
    uint32_t buffer_space = 64 - (ctx->count % 64);
    uint32_t buffer_pos = ctx->count % 64;
    
    ctx->count += length;
    
    if (length >= buffer_space) {
        for (uint32_t i = 0; i < buffer_space; i++) {
            ctx->buffer[buffer_pos + i] = data[i];
        }
        sha256_transform(ctx);
        
        data += buffer_space;
        length -= buffer_space;
        buffer_pos = 0;
        
        while (length >= 64) {
            for (int i = 0; i < 64; i++) {
                ctx->buffer[i] = data[i];
            }
            sha256_transform(ctx);
            data += 64;
            length -= 64;
        }
    }
    
    for (uint32_t i = 0; i < length; i++) {
        ctx->buffer[buffer_pos + i] = data[i];
    }
    
    ctx->checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
}

void crypto_sha256_final(crypto_sha256_context_t* ctx, uint8_t* digest) {
    if (!crypto_validate_sha256_context(ctx) || !digest) return;
    
    uint32_t buffer_pos = ctx->count % 64;
    
    ctx->buffer[buffer_pos++] = 0x80;
    
    if (buffer_pos > 56) {
        while (buffer_pos < 64) {
            ctx->buffer[buffer_pos++] = 0;
        }
        sha256_transform(ctx);
        buffer_pos = 0;
    }
    
    while (buffer_pos < 56) {
        ctx->buffer[buffer_pos++] = 0;
    }
    
    // Append length in bits
    uint64_t bit_count = ctx->count * 8;
    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (bit_count >> (56 - i*8)) & 0xFF;
    }
    
    sha256_transform(ctx);
    
    for (int i = 0; i < 8; i++) {
        digest[i*4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i*4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i*4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i*4 + 3] = ctx->state[i] & 0xFF;
    }
}

void crypto_sha256_destroy(crypto_sha256_context_t* ctx) {
    if (ctx) {
        crypto_secure_zero(ctx, sizeof(*ctx));
    }
}

bool crypto_sha256(const uint8_t* data, uint32_t length, uint8_t* digest) {
    if (!crypto_initialized || !data || !digest) return false;
    
    crypto_sha256_context_t ctx;
    if (!crypto_sha256_init(&ctx)) return false;
    
    crypto_sha256_update(&ctx, data, length);
    crypto_sha256_final(&ctx, digest);
    crypto_sha256_destroy(&ctx);
    
    return true;
}

// SHA-512

bool crypto_sha512_init(crypto_sha512_context_t* ctx) {
    if (!crypto_initialized || !ctx) return false;
    
    crypto_secure_zero(ctx, sizeof(*ctx));
    ctx->magic = CRYPTO_CONTEXT_MAGIC;
    init_context_guards(ctx->guard_pre, ctx->guard_post, CRYPTO_CONTEXT_MAGIC);
    
    // SHA-512 initial hash values (first 64 bits of fractional parts of square roots of primes)
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->count = 0;
    
    ctx->checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
    return true;
}

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define SHA512_BLOCK 128
#define SHA512_LENGTH_OFFSET 112
#define SHA512_ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHA512_EP0(x) (SHA512_ROTR(x, 28) ^ SHA512_ROTR(x, 34) ^ SHA512_ROTR(x, 39))
#define SHA512_EP1(x) (SHA512_ROTR(x, 14) ^ SHA512_ROTR(x, 18) ^ SHA512_ROTR(x, 41))
#define SHA512_SIG0(x) (SHA512_ROTR(x, 1) ^ SHA512_ROTR(x, 8) ^ ((x) >> 7))
#define SHA512_SIG1(x) (SHA512_ROTR(x, 19) ^ SHA512_ROTR(x, 61) ^ ((x) >> 6))

static void sha512_transform(crypto_sha512_context_t* ctx) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        for (int j = 0; j < 8; j++) {
            w[i] = (w[i] << 8) | ctx->buffer[i * 8 + j];
        }
    }
    for (int i = 16; i < 80; i++) {
        w[i] = SHA512_SIG1(w[i - 2]) + w[i - 7] + SHA512_SIG0(w[i - 15]) + w[i - 16];
    }

    uint64_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint64_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + SHA512_EP1(e) + ((e & f) ^ (~e & g)) + sha512_k[i] + w[i];
        uint64_t t2 = SHA512_EP0(a) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    crypto_secure_zero(w, sizeof(w));
}

void crypto_sha512_update(crypto_sha512_context_t* ctx, const uint8_t* data, uint32_t length) {
    if (!crypto_validate_sha512_context(ctx) || !data) return;

    for (uint32_t i = 0; i < length; i++) {
        ctx->buffer[ctx->count % SHA512_BLOCK] = data[i];
        ctx->count++;
        if (ctx->count % SHA512_BLOCK == 0) {
            sha512_transform(ctx);
        }
    }
    ctx->checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
}

// Pads to 112 bytes, then a 128 bit big endian length whose high half is always zero here
void crypto_sha512_final(crypto_sha512_context_t* ctx, uint8_t* digest) {
    if (!crypto_validate_sha512_context(ctx) || !digest) return;

    uint32_t pos = ctx->count % SHA512_BLOCK;
    ctx->buffer[pos++] = 0x80;
    if (pos > SHA512_LENGTH_OFFSET) {
        while (pos < SHA512_BLOCK) ctx->buffer[pos++] = 0;
        sha512_transform(ctx);
        pos = 0;
    }
    while (pos < SHA512_BLOCK - 8) ctx->buffer[pos++] = 0;

    uint64_t bit_count = ctx->count * 8;
    for (int i = 0; i < 8; i++) {
        ctx->buffer[SHA512_BLOCK - 8 + i] = (bit_count >> (56 - i * 8)) & 0xFF;
    }
    sha512_transform(ctx);

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            digest[i*8 + j] = (ctx->state[i] >> (56 - j*8)) & 0xFF;
        }
    }
}

void crypto_sha512_destroy(crypto_sha512_context_t* ctx) {
    if (ctx) {
        crypto_secure_zero(ctx, sizeof(*ctx));
    }
}

bool crypto_sha512(const uint8_t* data, uint32_t length, uint8_t* digest) {
    if (!crypto_initialized || !data || !digest) return false;

    crypto_sha512_context_t ctx;
    if (!crypto_sha512_init(&ctx)) return false;
    crypto_sha512_update(&ctx, data, length);
    crypto_sha512_final(&ctx, digest);
    crypto_sha512_destroy(&ctx);
    return true;
}

// HMAC

bool crypto_hmac_init(crypto_hmac_context_t* ctx, crypto_hash_t hash_type, 
                     const uint8_t* key, uint32_t key_size) {
    if (!crypto_initialized || !ctx || !key || key_size == 0) {
        return false;
    }
    
    crypto_secure_zero(ctx, sizeof(*ctx));
    ctx->magic = CRYPTO_CONTEXT_MAGIC;
    init_context_guards(ctx->guard_pre, ctx->guard_post, CRYPTO_CONTEXT_MAGIC);
    
    ctx->hash_type = hash_type;
    uint32_t block_size = (hash_type == CRYPTO_HASH_SHA256) ? 64 : 128;
    ctx->digest_size = (hash_type == CRYPTO_HASH_SHA256) ? 32 : 64;
    
    uint8_t key_buffer[128] = {0};
    if (key_size > block_size) {
        // Hash the key if it's too long
        if (hash_type == CRYPTO_HASH_SHA256) {
            crypto_sha256(key, key_size, key_buffer);
        } else {
            crypto_sha512(key, key_size, key_buffer);
        }
    } else {
        for (uint32_t i = 0; i < key_size; i++) {
            key_buffer[i] = key[i];
        }
    }
    
    uint8_t i_key_pad[128];
    uint8_t o_key_pad[128];
    
    for (uint32_t i = 0; i < block_size; i++) {
        i_key_pad[i] = key_buffer[i] ^ 0x36;
        o_key_pad[i] = key_buffer[i] ^ 0x5c;
    }
    
    for (uint32_t i = 0; i < block_size; i++) {
        ctx->key_pad[i] = o_key_pad[i];
    }
    
    if (hash_type == CRYPTO_HASH_SHA256) {
        crypto_sha256_init(&ctx->hash_ctx.sha256);
        crypto_sha256_update(&ctx->hash_ctx.sha256, i_key_pad, block_size);
    } else {
        crypto_sha512_init(&ctx->hash_ctx.sha512);
        crypto_sha512_update(&ctx->hash_ctx.sha512, i_key_pad, block_size);
    }
    
    // Clear sensitive data
    crypto_secure_zero(key_buffer, sizeof(key_buffer));
    crypto_secure_zero(i_key_pad, sizeof(i_key_pad));
    crypto_secure_zero(o_key_pad, sizeof(o_key_pad));
    
    ctx->checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
    return true;
}

void crypto_hmac_update(crypto_hmac_context_t* ctx, const uint8_t* data, uint32_t length) {
    if (!crypto_validate_hmac_context(ctx) || !data) return;
    
    if (ctx->hash_type == CRYPTO_HASH_SHA256) {
        crypto_sha256_update(&ctx->hash_ctx.sha256, data, length);
    } else {
        crypto_sha512_update(&ctx->hash_ctx.sha512, data, length);
    }
    
    ctx->checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
}

void crypto_hmac_final(crypto_hmac_context_t* ctx, uint8_t* mac) {
    if (!crypto_validate_hmac_context(ctx) || !mac) return;
    
    uint8_t inner_hash[64];
    uint32_t block_size = (ctx->hash_type == CRYPTO_HASH_SHA256) ? 64 : 128;
    
    if (ctx->hash_type == CRYPTO_HASH_SHA256) {
        crypto_sha256_final(&ctx->hash_ctx.sha256, inner_hash);
    } else {
        crypto_sha512_final(&ctx->hash_ctx.sha512, inner_hash);
    }
    
    if (ctx->hash_type == CRYPTO_HASH_SHA256) {
        crypto_sha256_context_t outer;
        crypto_sha256_init(&outer);
        crypto_sha256_update(&outer, ctx->key_pad, block_size);
        crypto_sha256_update(&outer, inner_hash, ctx->digest_size);
        crypto_sha256_final(&outer, mac);
        crypto_sha256_destroy(&outer);
    } else {
        crypto_sha512_context_t outer;
        crypto_sha512_init(&outer);
        crypto_sha512_update(&outer, ctx->key_pad, block_size);
        crypto_sha512_update(&outer, inner_hash, ctx->digest_size);
        crypto_sha512_final(&outer, mac);
        crypto_sha512_destroy(&outer);
    }
    
    crypto_secure_zero(inner_hash, sizeof(inner_hash));
}

void crypto_hmac_destroy(crypto_hmac_context_t* ctx) {
    if (ctx) {
        crypto_secure_zero(ctx, sizeof(*ctx));
    }
}

bool crypto_hmac(crypto_hash_t hash_type, const uint8_t* key, uint32_t key_size,
                const uint8_t* data, uint32_t data_size, uint8_t* mac) {
    if (!crypto_initialized || !key || !data || !mac) return false;
    
    crypto_hmac_context_t ctx;
    if (!crypto_hmac_init(&ctx, hash_type, key, key_size)) return false;
    
    crypto_hmac_update(&ctx, data, data_size);
    crypto_hmac_final(&ctx, mac);
    crypto_hmac_destroy(&ctx);
    
    return true;
}

// Utilities

bool crypto_secure_compare(const uint8_t* a, const uint8_t* b, uint32_t length) {
    if (!a || !b) return false;
    
    uint8_t result = 0;
    for (uint32_t i = 0; i < length; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

void crypto_secure_zero(void* ptr, uint32_t size) {
    if (!ptr) return;
    
    // Prevent compiler optimization by using volatile
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    for (uint32_t i = 0; i < size; i++) {
        p[i] = 0;
    }
    
    // Memory barrier to ensure writes complete
    __asm__ volatile("" ::: "memory");
}

uint32_t crypto_padding_pkcs7_add(uint8_t* buffer, uint32_t data_size, 
                                 uint32_t buffer_size, uint8_t block_size) {
    if (!buffer || data_size >= buffer_size || block_size == 0) {
        return 0;
    }
    
    uint8_t padding_length = block_size - (data_size % block_size);
    if (data_size + padding_length > buffer_size) {
        return 0;
    }
    
    for (uint8_t i = 0; i < padding_length; i++) {
        buffer[data_size + i] = padding_length;
    }
    
    return data_size + padding_length;
}

bool crypto_padding_pkcs7_remove(uint8_t* buffer, uint32_t* data_size, uint8_t block_size) {
    if (!buffer || !data_size || *data_size == 0 || block_size == 0) {
        return false;
    }
    
    uint8_t padding_length = buffer[*data_size - 1];
    
    uint8_t valid = 1;
    valid &= (padding_length > 0);
    valid &= (padding_length <= block_size);
    valid &= (padding_length <= *data_size);
    
    for (uint32_t i = *data_size - padding_length; i < *data_size; i++) {
        valid &= (buffer[i] == padding_length);
    }
    
    if (valid) {
        *data_size -= padding_length;
        return true;
    }
    
    return false;
}

bool crypto_validate_aes_context(const crypto_aes_context_t* ctx) {
    if (!ctx) return false;
    if (ctx->magic != CRYPTO_CONTEXT_MAGIC) return false;
    if (!check_context_guards(ctx->guard_pre, ctx->guard_post, CRYPTO_CONTEXT_MAGIC)) return false;
    
    uint32_t expected_checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
    return ctx->checksum == expected_checksum;
}

bool crypto_validate_sha256_context(const crypto_sha256_context_t* ctx) {
    if (!ctx) return false;
    if (ctx->magic != CRYPTO_CONTEXT_MAGIC) return false;
    if (!check_context_guards(ctx->guard_pre, ctx->guard_post, CRYPTO_CONTEXT_MAGIC)) return false;
    
    uint32_t expected_checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
    return ctx->checksum == expected_checksum;
}

bool crypto_validate_sha512_context(const crypto_sha512_context_t* ctx) {
    if (!ctx) return false;
    if (ctx->magic != CRYPTO_CONTEXT_MAGIC) return false;
    if (!check_context_guards(ctx->guard_pre, ctx->guard_post, CRYPTO_CONTEXT_MAGIC)) return false;
    
    uint32_t expected_checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
    return ctx->checksum == expected_checksum;
}

bool crypto_validate_hmac_context(const crypto_hmac_context_t* ctx) {
    if (!ctx) return false;
    if (ctx->magic != CRYPTO_CONTEXT_MAGIC) return false;
    if (!check_context_guards(ctx->guard_pre, ctx->guard_post, CRYPTO_CONTEXT_MAGIC)) return false;
    
    uint32_t expected_checksum = calculate_checksum(ctx, (uint32_t)((const uint8_t*)&ctx->checksum - (const uint8_t*)ctx));
    return ctx->checksum == expected_checksum;
}

// Init and self-test

bool crypto_initialize(void) {
    if (crypto_initialized) return true;
    
    terminal_write_string("CRYPTO: Initializing cryptographic subsystem...\n");
    
    crypto_secure_zero(&entropy_state, sizeof(entropy_state));
    entropy_state.stats.active_sources = 0;
    
    if (!crypto_detect_entropy_sources()) {
        terminal_write_string("CRYPTO: WARNING - No entropy sources available\n");
        return false;
    }
    
    terminal_write_string("CRYPTO: Collecting initial entropy...\n");
    
    for (int i = 0; i < 10; i++) {
        crypto_add_entropy_rdrand();
        crypto_add_entropy_rdseed();
        crypto_add_entropy_jitter();
    }
    
    if (entropy_state.available_bits < CRYPTO_MIN_ENTROPY_BITS) {
        terminal_write_string("CRYPTO: WARNING - Insufficient initial entropy\n");
        terminal_write_string("CRYPTO: Available: ");
        terminal_write_uint(entropy_state.available_bits);
        terminal_write_string(" bits, Required: ");
        terminal_write_uint(CRYPTO_MIN_ENTROPY_BITS);
        terminal_write_string(" bits\n");
    } else {
        terminal_write_string("CRYPTO: Initial entropy collected: ");
        terminal_write_uint(entropy_state.available_bits);
        terminal_write_string(" bits\n");
    }
    
    crypto_initialized = true;
    
    terminal_write_string("CRYPTO: Cryptographic subsystem initialized\n");
    terminal_write_string("CRYPTO: Available algorithms:\n");
    terminal_write_string("  - AES-128/256 (CBC, CTR modes)\n");
    terminal_write_string("  - SHA-256/512\n");
    terminal_write_string("  - HMAC-SHA256/512\n");
    terminal_write_string("  - Secure RNG (RDRAND/RDSEED/Jitter)\n");
    terminal_write_string("CRYPTO: RSA operations removed (use userspace)\n");
    
    return true;
}

void crypto_shutdown(void) {
    if (!crypto_initialized) return;
    
    terminal_write_string("CRYPTO: Shutting down cryptographic subsystem\n");
    
    crypto_secure_zero(&entropy_state, sizeof(entropy_state));
    
    crypto_initialized = false;
    terminal_write_string("CRYPTO: Cryptographic subsystem shutdown complete\n");
}

static const uint8_t kat_abc[3] = {'a', 'b', 'c'};

static const uint8_t kat_sha256_abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static const uint8_t kat_sha512_abc[64] = {
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
};

// FIPS 197 appendix C, the key bytes count up from zero
static const uint8_t kat_aes_plain[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const uint8_t kat_aes128_cipher[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};
static const uint8_t kat_aes256_cipher[16] = {
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
};

// RFC 4231 test case 1
static const uint8_t kat_hmac_data[8] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
static const uint8_t kat_hmac_sha256[32] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
};

#define KAT_HMAC_KEY_SIZE 20
#define KAT_HMAC_KEY_BYTE 0x0b

static bool kat_report(const char* name, bool ok) {
    terminal_write_string("CRYPTO: ");
    terminal_write_string(name);
    terminal_write_string(ok ? " known answer PASSED\n" : " known answer FAILED\n");
    return ok;
}

static bool kat_aes(crypto_cipher_t cipher, uint8_t key_size, const uint8_t* expected) {
    uint8_t key[32];
    for (uint8_t i = 0; i < key_size; i++) key[i] = i;
    crypto_aes_context_t ctx;
    uint8_t out[16];
    uint8_t back[16];
    bool ok = crypto_aes_init(&ctx, cipher, key, NULL) &&
              crypto_aes_encrypt_block(&ctx, kat_aes_plain, out) &&
              crypto_secure_compare(out, expected, 16) &&
              crypto_aes_decrypt_block(&ctx, out, back) &&
              crypto_secure_compare(back, kat_aes_plain, 16);
    crypto_aes_destroy(&ctx);
    return ok;
}

static bool crypto_known_answer_tests(void) {
    uint8_t digest[64];
    bool ok = true;

    ok &= kat_report("SHA-256", crypto_sha256(kat_abc, sizeof(kat_abc), digest) &&
                     crypto_secure_compare(digest, kat_sha256_abc, 32));
    ok &= kat_report("SHA-512", crypto_sha512(kat_abc, sizeof(kat_abc), digest) &&
                     crypto_secure_compare(digest, kat_sha512_abc, 64));
    ok &= kat_report("AES-128", kat_aes(CRYPTO_CIPHER_AES_128_ECB, 16, kat_aes128_cipher));
    ok &= kat_report("AES-256", kat_aes(CRYPTO_CIPHER_AES_256_ECB, 32, kat_aes256_cipher));

    uint8_t hmac_key[KAT_HMAC_KEY_SIZE];
    for (int i = 0; i < KAT_HMAC_KEY_SIZE; i++) hmac_key[i] = KAT_HMAC_KEY_BYTE;
    ok &= kat_report("HMAC-SHA256", crypto_hmac(CRYPTO_HASH_SHA256, hmac_key, sizeof(hmac_key),
                                                kat_hmac_data, sizeof(kat_hmac_data), digest) &&
                     crypto_secure_compare(digest, kat_hmac_sha256, 32));
    return ok;
}

bool crypto_self_test(void) {
    if (!crypto_initialized) {
        terminal_write_string("CRYPTO: Self-test failed - not initialized\n");
        return false;
    }
    
    terminal_write_string("CRYPTO: Running self-tests...\n");

    if (!crypto_known_answer_tests()) {
        terminal_write_string("CRYPTO: Self-test FAILED - known answer mismatch\n");
        return false;
    }

    uint8_t random_data[32];
    if (!crypto_rng_get_bytes(random_data, sizeof(random_data))) {
        terminal_write_string("CRYPTO: Self-test FAILED - RNG error\n");
        return false;
    }
    
    const uint8_t test_input[] = "test data";
    uint8_t hash[32];
    if (!crypto_sha256(test_input, sizeof(test_input) - 1, hash)) {
        terminal_write_string("CRYPTO: Self-test FAILED - SHA-256 error\n");
        return false;
    }
    
    uint8_t key[32];
    uint8_t iv[16];
    crypto_rng_get_bytes(key, sizeof(key));
    crypto_rng_get_bytes(iv, sizeof(iv));
    
    crypto_aes_context_t aes_ctx;
    if (!crypto_aes_init(&aes_ctx, CRYPTO_CIPHER_AES_256_CBC, key, iv)) {
        terminal_write_string("CRYPTO: Self-test FAILED - AES init error\n");
        return false;
    }
    
    uint8_t plaintext[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    if (!crypto_aes_encrypt_block(&aes_ctx, plaintext, ciphertext)) {
        terminal_write_string("CRYPTO: Self-test FAILED - AES encrypt error\n");
        crypto_aes_destroy(&aes_ctx);
        return false;
    }
    
    // Reinit for decryption
    crypto_aes_init(&aes_ctx, CRYPTO_CIPHER_AES_256_CBC, key, iv);
    
    if (!crypto_aes_decrypt_block(&aes_ctx, ciphertext, decrypted)) {
        terminal_write_string("CRYPTO: Self-test FAILED - AES decrypt error\n");
        crypto_aes_destroy(&aes_ctx);
        return false;
    }
    
    if (!crypto_secure_compare(plaintext, decrypted, 16)) {
        terminal_write_string("CRYPTO: Self-test FAILED - AES round-trip mismatch\n");
        crypto_aes_destroy(&aes_ctx);
        return false;
    }
    
    crypto_aes_destroy(&aes_ctx);
    
    uint8_t hmac_key[32];
    uint8_t mac[32];
    crypto_rng_get_bytes(hmac_key, sizeof(hmac_key));
    
    if (!crypto_hmac(CRYPTO_HASH_SHA256, hmac_key, sizeof(hmac_key), 
                     test_input, sizeof(test_input) - 1, mac)) {
        terminal_write_string("CRYPTO: Self-test FAILED - HMAC error\n");
        return false;
    }
    
    terminal_write_string("CRYPTO: All self-tests PASSED\n");
    return true;
}
#ifndef APOLLO_RATE_LIMITER_H
#define APOLLO_RATE_LIMITER_H

#include "types.h"
#include "network_interface.h"
#include "ip_stack.h"

#define RATE_LIMITER_MAX_BUCKETS 1024
#define RATE_LIMITER_MAX_RULES 256
#define RATE_LIMITER_CLEANUP_INTERVAL 60000  // 1 minute
#define RATE_LIMITER_BUCKET_TIMEOUT 300000   // 5 minutes

typedef enum {
    RATE_LIMIT_TOKEN_BUCKET = 0,
    RATE_LIMIT_SLIDING_WINDOW = 1,
    RATE_LIMIT_FIXED_WINDOW = 2
} rate_limit_algorithm_t;

typedef enum {
    RATE_LIMIT_GLOBAL = 0,
    RATE_LIMIT_PER_IP = 1,
    RATE_LIMIT_PER_PORT = 2,
    RATE_LIMIT_PER_CONNECTION = 3, // Keyed on source and destination address and port
    RATE_LIMIT_PER_SUBNET = 4
} rate_limit_scope_t;

typedef enum {
    RATE_LIMIT_ACTION_ALLOW = 0,
    RATE_LIMIT_ACTION_DROP = 1,
    RATE_LIMIT_ACTION_DELAY = 2,
    RATE_LIMIT_ACTION_REJECT = 3
} rate_limit_action_t;

typedef struct {
    uint32_t rule_id;
    bool enabled;
    
    rate_limit_scope_t scope;
    uint8_t protocol;  // 0 = any, 6 = TCP, 17 = UDP, etc.
    ip_address_t network;
    ip_address_t netmask;
    uint16_t port_start;
    uint16_t port_end;
    
    rate_limit_algorithm_t algorithm;
    uint32_t max_rate;        // packets/bytes per second
    uint32_t burst_size;      // maximum burst
    uint32_t window_size;     // window size in seconds
    bool count_bytes;         // true = count bytes, false = count packets
    
    rate_limit_action_t action;
    uint32_t delay_ms;        // delay time for DELAY action
    
    uint32_t violation_threshold;  // violations before blocking
    uint32_t block_duration;       // seconds to block after violations
    
    uint64_t packets_processed;
    uint64_t packets_allowed;
    uint64_t packets_limited;
    uint64_t bytes_processed;
    uint64_t violations;
    
    char description[64];
} rate_limit_rule_t;

typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t packets_allowed;
    uint64_t packets_limited;
    uint64_t packets_dropped;
    uint64_t active_buckets;
    uint64_t rules_processed;
    uint32_t current_violations;
} rate_limiter_stats_t;

bool rate_limiter_initialize(void);
bool rate_limiter_is_enabled(void);
bool rate_limiter_check_packet(const ip_header_t* ip, const void* payload, uint32_t length);
bool rate_limiter_get_rule_at(uint32_t index, rate_limit_rule_t* rule);
void rate_limiter_shutdown(void);
uint32_t rate_limiter_add_rule(const rate_limit_rule_t* rule);
bool rate_limiter_remove_rule(uint32_t rule_id);
bool rate_limiter_enable_rule(uint32_t rule_id);
bool rate_limiter_disable_rule(uint32_t rule_id);
bool rate_limiter_get_rule(uint32_t rule_id, rate_limit_rule_t* rule);
uint32_t rate_limiter_get_rule_count(void);
void rate_limiter_process_timers(void);
rate_limiter_stats_t* rate_limiter_get_statistics(void);
void rate_limiter_reset_statistics(void);
void rate_limiter_clear_buckets(void);
uint32_t rate_limiter_get_bucket_count(void);
uint32_t rate_limiter_add_global_limit(uint32_t pps, uint32_t burst);
uint32_t rate_limiter_add_per_ip_limit(uint32_t pps, uint32_t burst);
uint32_t rate_limiter_add_port_limit(uint16_t port, uint32_t pps, uint32_t burst);
uint32_t rate_limiter_add_ddos_protection(void);

#endif
#include "rate_limiter.h"
#include "heap_allocator.h"
#include "terminal.h"
#include "string_utils.h"
#include "time_keeper.h"

#define MS_PER_SECOND 1000
#define TOKEN_SCALE 1000
#define PORT_HEADER_BYTES 4
#define MAX_DELAY_MS 100
#define DDOS_GLOBAL_PPS 10000
#define DDOS_GLOBAL_BURST 1000
#define DDOS_PER_IP_PPS 100
#define DDOS_PER_IP_BURST 50
#define DDOS_WEB_PPS 50
#define DDOS_WEB_BURST 20
#define DDOS_SSH_PPS 10
#define DDOS_SSH_BURST 5
#define HTTP_PORT 80
#define HTTPS_PORT 443
#define SSH_PORT 22
#define DEFAULT_VIOLATION_THRESHOLD 10
#define DEFAULT_BLOCK_SECONDS 60

typedef struct {
    uint32_t rule_id;
    uint32_t key;
    uint64_t tokens;
    uint32_t last_refill;
    uint32_t window_start;
    uint32_t window_count;
    uint32_t previous_count;
    uint32_t violations;
    uint32_t blocked_until;
    bool active;
} rate_bucket_t;

static rate_limit_rule_t rules[RATE_LIMITER_MAX_RULES];
static uint32_t rule_count = 0;
static uint32_t next_rule_id = 1;
static rate_bucket_t buckets[RATE_LIMITER_MAX_BUCKETS];
static rate_limiter_stats_t rl_stats = {0};
static bool rl_enabled = false;

static void zero_bytes(void* dest, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) d[i] = 0;
}

static uint32_t bucket_key(const rate_limit_rule_t* r, const ip_header_t* ip, uint16_t src_port, uint16_t dst_port) {
    switch (r->scope) {
        case RATE_LIMIT_GLOBAL: return 0;
        case RATE_LIMIT_PER_IP: return ip->source_ip.addr;
        case RATE_LIMIT_PER_PORT: return dst_port;
        case RATE_LIMIT_PER_SUBNET: return ip->source_ip.addr & r->netmask.addr;
        case RATE_LIMIT_PER_CONNECTION:
            return ip->source_ip.addr ^ (ip->dest_ip.addr * 31) ^ ((uint32_t)src_port << 16) ^ dst_port;
    }
    return 0;
}

static rate_bucket_t* find_bucket(uint32_t rule_id, uint32_t key, uint32_t now, uint64_t capacity) {
    rate_bucket_t* free_slot = NULL;
    for (uint32_t i = 0; i < RATE_LIMITER_MAX_BUCKETS; i++) {
        rate_bucket_t* b = &buckets[i];
        if (b->active && b->rule_id == rule_id && b->key == key) return b;
        if (!b->active && !free_slot) free_slot = b;
    }
    if (!free_slot) return NULL;
    zero_bytes(free_slot, sizeof(*free_slot));
    free_slot->rule_id = rule_id;
    free_slot->key = key;
    free_slot->tokens = capacity;
    free_slot->last_refill = now;
    free_slot->window_start = now;
    free_slot->active = true;
    rl_stats.active_buckets++;
    return free_slot;
}

static bool token_bucket_allows(const rate_limit_rule_t* r, rate_bucket_t* b, uint32_t now, uint32_t cost) {
    uint64_t capacity = (uint64_t)(r->burst_size ? r->burst_size : r->max_rate) * TOKEN_SCALE;
    uint64_t refill = (uint64_t)(now - b->last_refill) * r->max_rate;
    b->last_refill = now;
    b->tokens = (b->tokens + refill > capacity) ? capacity : b->tokens + refill;
    uint64_t needed = (uint64_t)cost * TOKEN_SCALE;
    if (b->tokens < needed) return false;
    b->tokens -= needed;
    return true;
}

static void roll_window(rate_bucket_t* b, uint32_t now, uint32_t window_ms) {
    uint32_t elapsed = now - b->window_start;
    if (elapsed < window_ms) return;
    b->previous_count = (elapsed < 2 * window_ms) ? b->window_count : 0;
    b->window_count = 0;
    b->window_start = now - (elapsed % window_ms);
}

// Sliding window weights the previous window by how much of it still overlaps
static bool window_allows(const rate_limit_rule_t* r, rate_bucket_t* b, uint32_t now, uint32_t cost) {
    uint32_t window_ms = (r->window_size ? r->window_size : 1) * MS_PER_SECOND;
    uint64_t limit = (uint64_t)r->max_rate * (window_ms / MS_PER_SECOND);
    roll_window(b, now, window_ms);
    uint64_t used = b->window_count;
    if (r->algorithm == RATE_LIMIT_SLIDING_WINDOW) {
        uint32_t into = now - b->window_start;
        used += (uint64_t)b->previous_count * (window_ms - into) / window_ms;
    }
    if (used + cost > limit) return false;
    b->window_count += cost;
    return true;
}

static bool rule_applies(const rate_limit_rule_t* r, const ip_header_t* ip, uint16_t dst_port) {
    if (!r->enabled) return false;
    if (r->protocol && r->protocol != ip->protocol) return false;
    if (r->port_end && (dst_port < r->port_start || dst_port > r->port_end)) return false;
    if (r->netmask.addr && (ip->source_ip.addr & r->netmask.addr) != (r->network.addr & r->netmask.addr)) {
        return false;
    }
    return true;
}

static rate_limit_action_t apply_rule(rate_limit_rule_t* r, const ip_header_t* ip, uint16_t src_port,
                                      uint16_t dst_port, uint32_t length, uint32_t now) {
    uint64_t capacity = (uint64_t)(r->burst_size ? r->burst_size : r->max_rate) * TOKEN_SCALE;
    rate_bucket_t* b = find_bucket(r->rule_id, bucket_key(r, ip, src_port, dst_port), now, capacity);
    r->packets_processed++;
    r->bytes_processed += length;
    if (!b) return RATE_LIMIT_ACTION_ALLOW;

    if (b->blocked_until && now < b->blocked_until) {
        r->packets_limited++;
        return RATE_LIMIT_ACTION_DROP;
    }
    uint32_t cost = r->count_bytes ? length : 1;
    bool allowed = (r->algorithm == RATE_LIMIT_TOKEN_BUCKET)
        ? token_bucket_allows(r, b, now, cost)
        : window_allows(r, b, now, cost);
    if (allowed) {
        r->packets_allowed++;
        return RATE_LIMIT_ACTION_ALLOW;
    }

    r->packets_limited++;
    r->violations++;
    b->violations++;
    rl_stats.current_violations++;
    if (r->violation_threshold && b->violations >= r->violation_threshold && r->block_duration) {
        b->blocked_until = now + r->block_duration * MS_PER_SECOND;
        b->violations = 0;
    }
    return r->action;
}

bool rate_limiter_check_packet(const ip_header_t* ip, const void* payload, uint32_t length) {
    if (!rl_enabled || !ip) return true;
    const uint8_t* bytes = (const uint8_t*)payload;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (length >= PORT_HEADER_BYTES && (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP)) {
        src_port = (uint16_t)((bytes[0] << 8) | bytes[1]);
        dst_port = (uint16_t)((bytes[2] << 8) | bytes[3]);
    }

    rl_stats.total_packets++;
    rl_stats.total_bytes += length;
    uint32_t now = get_system_time();
    for (uint32_t i = 0; i < rule_count; i++) {
        rate_limit_rule_t* r = &rules[i];
        if (!rule_applies(r, ip, dst_port)) continue;
        rl_stats.rules_processed++;
        rate_limit_action_t action = apply_rule(r, ip, src_port, dst_port, length, now);
        if (action == RATE_LIMIT_ACTION_DELAY) {
            time_keeper_delay_ms(r->delay_ms > MAX_DELAY_MS ? MAX_DELAY_MS : r->delay_ms);
            continue;
        }
        if (action != RATE_LIMIT_ACTION_ALLOW) {
            rl_stats.packets_limited++;
            rl_stats.packets_dropped++;
            return false;
        }
    }
    rl_stats.packets_allowed++;
    return true;
}

bool rate_limiter_initialize(void) {
    if (rl_enabled) return true;
    zero_bytes(buckets, sizeof(buckets));
    rl_stats = (rate_limiter_stats_t){0};
    rl_enabled = true;
    terminal_write_string("RATE_LIMITER: enabled, rules: ");
    terminal_write_uint(rule_count);
    terminal_write_string("\n");
    return true;
}

// Rules are kept so enabling again restores them
void rate_limiter_shutdown(void) {
    rl_enabled = false;
    zero_bytes(buckets, sizeof(buckets));
    rl_stats.active_buckets = 0;
    terminal_write_string("RATE_LIMITER: disabled\n");
}

bool rate_limiter_is_enabled(void) {
    return rl_enabled;
}

uint32_t rate_limiter_add_rule(const rate_limit_rule_t* rule) {
    if (!rule || rule_count >= RATE_LIMITER_MAX_RULES || rule->max_rate == 0) return 0;
    rate_limit_rule_t* slot = &rules[rule_count++];
    *slot = *rule;
    slot->rule_id = next_rule_id++;
    slot->enabled = true;
    slot->packets_processed = 0;
    slot->packets_allowed = 0;
    slot->packets_limited = 0;
    slot->bytes_processed = 0;
    slot->violations = 0;
    return slot->rule_id;
}

static int32_t find_rule_index(uint32_t rule_id) {
    for (uint32_t i = 0; i < rule_count; i++) {
        if (rules[i].rule_id == rule_id) return (int32_t)i;
    }
    return -1;
}

static void release_rule_buckets(uint32_t rule_id) {
    for (uint32_t i = 0; i < RATE_LIMITER_MAX_BUCKETS; i++) {
        if (buckets[i].active && buckets[i].rule_id == rule_id) {
            buckets[i].active = false;
            rl_stats.active_buckets--;
        }
    }
}

bool rate_limiter_remove_rule(uint32_t rule_id) {
    int32_t index = find_rule_index(rule_id);
    if (index < 0) return false;
    release_rule_buckets(rule_id);
    for (uint32_t i = (uint32_t)index; i + 1 < rule_count; i++) {
        rules[i] = rules[i + 1];
    }
    rule_count--;
    return true;
}

bool rate_limiter_enable_rule(uint32_t rule_id) {
    int32_t index = find_rule_index(rule_id);
    if (index < 0) return false;
    rules[index].enabled = true;
    return true;
}

bool rate_limiter_disable_rule(uint32_t rule_id) {
    int32_t index = find_rule_index(rule_id);
    if (index < 0) return false;
    rules[index].enabled = false;
    return true;
}

bool rate_limiter_get_rule(uint32_t rule_id, rate_limit_rule_t* rule) {
    int32_t index = find_rule_index(rule_id);
    if (index < 0 || !rule) return false;
    *rule = rules[index];
    return true;
}

bool rate_limiter_get_rule_at(uint32_t index, rate_limit_rule_t* rule) {
    if (index >= rule_count || !rule) return false;
    *rule = rules[index];
    return true;
}

uint32_t rate_limiter_get_rule_count(void) {
    return rule_count;
}

void rate_limiter_process_timers(void) {
    static uint32_t last_cleanup = 0;
    if (!rl_enabled) return;
    uint32_t now = get_system_time();
    if (now - last_cleanup < RATE_LIMITER_CLEANUP_INTERVAL) return;
    last_cleanup = now;
    for (uint32_t i = 0; i < RATE_LIMITER_MAX_BUCKETS; i++) {
        rate_bucket_t* b = &buckets[i];
        uint32_t idle = now - (b->last_refill > b->window_start ? b->last_refill : b->window_start);
        if (b->active && idle >= RATE_LIMITER_BUCKET_TIMEOUT && now >= b->blocked_until) {
            b->active = false;
            rl_stats.active_buckets--;
        }
    }
    rl_stats.current_violations = 0;
}

rate_limiter_stats_t* rate_limiter_get_statistics(void) {
    return rl_enabled ? &rl_stats : NULL;
}

void rate_limiter_reset_statistics(void) {
    uint64_t active = rl_stats.active_buckets;
    rl_stats = (rate_limiter_stats_t){0};
    rl_stats.active_buckets = active;
}

void rate_limiter_clear_buckets(void) {
    zero_bytes(buckets, sizeof(buckets));
    rl_stats.active_buckets = 0;
}

uint32_t rate_limiter_get_bucket_count(void) {
    return (uint32_t)rl_stats.active_buckets;
}

static uint32_t add_token_rule(rate_limit_scope_t scope, uint16_t port, uint32_t pps, uint32_t burst,
                               const char* description) {
    rate_limit_rule_t rule;
    zero_bytes(&rule, sizeof(rule));
    rule.scope = scope;
    rule.algorithm = RATE_LIMIT_TOKEN_BUCKET;
    rule.max_rate = pps;
    rule.burst_size = burst;
    rule.port_start = port;
    rule.port_end = port;
    rule.action = RATE_LIMIT_ACTION_DROP;
    rule.violation_threshold = DEFAULT_VIOLATION_THRESHOLD;
    rule.block_duration = DEFAULT_BLOCK_SECONDS;
    string_copy(rule.description, description);
    return rate_limiter_add_rule(&rule);
}

uint32_t rate_limiter_add_global_limit(uint32_t pps, uint32_t burst) {
    return add_token_rule(RATE_LIMIT_GLOBAL, 0, pps, burst, "Global rate limit");
}

uint32_t rate_limiter_add_per_ip_limit(uint32_t pps, uint32_t burst) {
    return add_token_rule(RATE_LIMIT_PER_IP, 0, pps, burst, "Per-IP rate limit");
}

uint32_t rate_limiter_add_port_limit(uint16_t port, uint32_t pps, uint32_t burst) {
    return add_token_rule(RATE_LIMIT_PER_PORT, port, pps, burst, "Port rate limit");
}

uint32_t rate_limiter_add_ddos_protection(void) {
    uint32_t added = 0;
    if (rate_limiter_add_global_limit(DDOS_GLOBAL_PPS, DDOS_GLOBAL_BURST)) added++;
    if (rate_limiter_add_per_ip_limit(DDOS_PER_IP_PPS, DDOS_PER_IP_BURST)) added++;
    if (rate_limiter_add_port_limit(HTTP_PORT, DDOS_WEB_PPS, DDOS_WEB_BURST)) added++;
    if (rate_limiter_add_port_limit(HTTPS_PORT, DDOS_WEB_PPS, DDOS_WEB_BURST)) added++;
    if (rate_limiter_add_port_limit(SSH_PORT, DDOS_SSH_PPS, DDOS_SSH_BURST)) added++;
    return added;
}
#ifndef APOLLO_FIREWALL_H
#define APOLLO_FIREWALL_H

#include "types.h"
#include "network_interface.h"
#include "ip_stack.h"

#define FIREWALL_MAX_RULES 512
#define FIREWALL_MAX_CONNECTIONS 2048
#define FIREWALL_CONNECTION_TIMEOUT 300000  // 5 minutes in ms
#define FIREWALL_MAX_PORTS_PER_RULE 32
#define FIREWALL_MAX_IPS_PER_RULE 16

typedef enum {
    FIREWALL_ACTION_ALLOW = 0,
    FIREWALL_ACTION_DENY = 1,
    FIREWALL_ACTION_DROP = 2,    // Silent drop
    FIREWALL_ACTION_REJECT = 3,  // Send ICMP unreachable
    FIREWALL_ACTION_LOG = 4      // Log and continue processing
} firewall_action_t;

typedef enum {
    FIREWALL_PROTO_ANY = 0,
    FIREWALL_PROTO_TCP = 6,
    FIREWALL_PROTO_UDP = 17,
    FIREWALL_PROTO_ICMP = 1
} firewall_protocol_t;

typedef enum {
    CONN_STATE_NEW = 0,
    CONN_STATE_ESTABLISHED = 1,
    CONN_STATE_RELATED = 2,
    CONN_STATE_INVALID = 3,
    CONN_STATE_CLOSING = 4
} connection_state_t;

typedef enum {
    FIREWALL_DIR_IN = 1,
    FIREWALL_DIR_OUT = 2,
    FIREWALL_DIR_BOTH = 3
} firewall_direction_t;

typedef struct {
    ip_address_t network;
    ip_address_t netmask;
} ip_range_t;

typedef struct {
    uint16_t start;
    uint16_t end;
} port_range_t;

typedef struct {
    uint32_t rule_id;
    bool enabled;
    firewall_direction_t direction;
    firewall_protocol_t protocol;
    
    ip_range_t src_ranges[FIREWALL_MAX_IPS_PER_RULE];
    uint8_t src_range_count;
    port_range_t src_ports[FIREWALL_MAX_PORTS_PER_RULE];
    uint8_t src_port_count;
    
    ip_range_t dst_ranges[FIREWALL_MAX_IPS_PER_RULE];
    uint8_t dst_range_count;
    port_range_t dst_ports[FIREWALL_MAX_PORTS_PER_RULE];
    uint8_t dst_port_count;
    
    bool match_new;
    bool match_established;
    bool match_related;
    
    firewall_action_t action;
    
    bool log_matches;
    char description[64];
    
    uint64_t match_count;
    uint64_t byte_count;
    uint32_t last_match_time;
} firewall_rule_t;

typedef struct {
    ip_address_t src_ip;
    ip_address_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    connection_state_t state;
    uint32_t creation_time;
    uint32_t last_activity;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t packets_in;
    uint64_t packets_out;
    
    struct {
        uint32_t seq_client;
        uint32_t seq_server;
        uint8_t tcp_state;
        bool syn_seen;
        bool fin_seen;
    } tcp_info;
    
    bool is_active;
    uint32_t hash;
} connection_entry_t;

typedef struct {
    uint64_t packets_processed;
    uint64_t packets_allowed;
    uint64_t packets_denied;
    uint64_t packets_dropped;
    uint64_t bytes_processed;
    uint64_t connections_tracked;
    uint64_t connections_expired;
    uint64_t rule_matches;
    uint32_t active_connections;
} firewall_stats_t;

bool firewall_initialize(void);
bool firewall_is_enabled(void);
firewall_action_t firewall_check_packet(firewall_direction_t direction, const ip_header_t* ip,
                                        const void* payload, uint32_t length);
bool firewall_get_rule_at(uint32_t index, firewall_rule_t* rule);
const char* firewall_action_name(firewall_action_t action);
void firewall_shutdown(void);
uint32_t firewall_add_rule(const firewall_rule_t* rule);
bool firewall_remove_rule(uint32_t rule_id);
bool firewall_enable_rule(uint32_t rule_id);
bool firewall_disable_rule(uint32_t rule_id);
bool firewall_get_rule(uint32_t rule_id, firewall_rule_t* rule);
uint32_t firewall_get_rule_count(void);
bool firewall_set_default_policy(firewall_direction_t direction, firewall_action_t action);
firewall_action_t firewall_get_default_policy(firewall_direction_t direction);
void firewall_process_timers(void);
void firewall_expire_connections(void);
firewall_stats_t* firewall_get_statistics(void);
void firewall_reset_statistics(void);
uint32_t firewall_get_active_connections(void);
void firewall_set_log_level(uint8_t level);
void firewall_enable_connection_logging(bool enable);

#endif
#include "firewall.h"
#include "heap_allocator.h"
#include "terminal.h"
#include "string_utils.h"
#include "time_keeper.h"

#define TCP_FLAGS_OFFSET 13
#define TCP_FLAG_FIN_BIT 0x01
#define TCP_FLAG_SYN_BIT 0x02
#define TCP_FLAG_RST_BIT 0x04
#define TCP_FLAG_ACK_BIT 0x10
#define PORT_HEADER_BYTES 4
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_UNREACHABLE_TYPE 3
#define ICMP_TIME_EXCEEDED_TYPE 11
#define DHCP_SERVER_PORT_NUMBER 67
#define DHCP_CLIENT_PORT_NUMBER 68
#define FIREWALL_TIMER_INTERVAL_MS 1000
#define LOG_LEVEL_MATCHES 1

static firewall_rule_t rules[FIREWALL_MAX_RULES];
static uint32_t rule_count = 0;
static uint32_t next_rule_id = 1;
static connection_entry_t connections[FIREWALL_MAX_CONNECTIONS];
static firewall_stats_t fw_stats = {0};
static bool fw_enabled = false;
static firewall_action_t default_policy_in = FIREWALL_ACTION_DENY;
static firewall_action_t default_policy_out = FIREWALL_ACTION_ALLOW;
static uint8_t log_level = 0;
static bool connection_logging = false;

typedef struct {
    firewall_direction_t direction;
    uint8_t protocol;
    ip_address_t src_ip;
    ip_address_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;
    uint32_t length;
} packet_info_t;

static void zero_bytes(void* dest, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) d[i] = 0;
}

static const char* action_name(firewall_action_t action) {
    switch (action) {
        case FIREWALL_ACTION_ALLOW: return "ALLOW";
        case FIREWALL_ACTION_DENY: return "DENY";
        case FIREWALL_ACTION_DROP: return "DROP";
        case FIREWALL_ACTION_REJECT: return "REJECT";
        case FIREWALL_ACTION_LOG: return "LOG";
    }
    return "UNKNOWN";
}

static uint32_t connection_hash(const packet_info_t* p) {
    return p->src_ip.addr ^ p->dst_ip.addr ^ ((uint32_t)p->src_port << 16) ^ p->dst_port ^ p->protocol;
}

// Outbound packets own the tuple, inbound replies match it reversed
static connection_entry_t* find_connection(const packet_info_t* p, bool* is_reply) {
    for (uint32_t i = 0; i < FIREWALL_MAX_CONNECTIONS; i++) {
        connection_entry_t* c = &connections[i];
        if (!c->is_active || c->protocol != p->protocol) continue;
        if (c->src_ip.addr == p->src_ip.addr && c->dst_ip.addr == p->dst_ip.addr &&
            c->src_port == p->src_port && c->dst_port == p->dst_port) {
            *is_reply = false;
            return c;
        }
        if (c->src_ip.addr == p->dst_ip.addr && c->dst_ip.addr == p->src_ip.addr &&
            c->src_port == p->dst_port && c->dst_port == p->src_port) {
            *is_reply = true;
            return c;
        }
    }
    return NULL;
}

static connection_entry_t* create_connection(const packet_info_t* p) {
    connection_entry_t* slot = NULL;
    connection_entry_t* oldest = &connections[0];
    for (uint32_t i = 0; i < FIREWALL_MAX_CONNECTIONS; i++) {
        if (!connections[i].is_active) {
            slot = &connections[i];
            break;
        }
        if (connections[i].last_activity < oldest->last_activity) oldest = &connections[i];
    }
    if (!slot) {
        slot = oldest;
        fw_stats.connections_expired++;
        fw_stats.active_connections--;
    }
    zero_bytes(slot, sizeof(*slot));
    slot->src_ip = p->src_ip;
    slot->dst_ip = p->dst_ip;
    slot->src_port = p->src_port;
    slot->dst_port = p->dst_port;
    slot->protocol = p->protocol;
    slot->state = CONN_STATE_NEW;
    slot->creation_time = get_system_time();
    slot->last_activity = slot->creation_time;
    slot->hash = connection_hash(p);
    slot->is_active = true;
    fw_stats.connections_tracked++;
    fw_stats.active_connections++;
    return slot;
}

static void update_tcp_state(connection_entry_t* c, const packet_info_t* p) {
    if (p->tcp_flags & TCP_FLAG_SYN_BIT) c->tcp_info.syn_seen = true;
    if (p->tcp_flags & (TCP_FLAG_FIN_BIT | TCP_FLAG_RST_BIT)) {
        c->tcp_info.fin_seen = true;
        c->state = CONN_STATE_CLOSING;
    }
    c->tcp_info.tcp_state = p->tcp_flags;
}

// Returns the connection state this packet belongs to and creates entries for new outbound flows
static connection_state_t track_packet(const packet_info_t* p) {
    bool is_reply = false;
    connection_entry_t* c = find_connection(p, &is_reply);
    if (!c) {
        if (p->direction == FIREWALL_DIR_OUT) {
            c = create_connection(p);
        } else {
            return CONN_STATE_NEW;
        }
    } else if (is_reply && c->state == CONN_STATE_NEW) {
        c->state = CONN_STATE_ESTABLISHED;
    }
    c->last_activity = get_system_time();
    if (p->direction == FIREWALL_DIR_IN) {
        c->packets_in++;
        c->bytes_in += p->length;
    } else {
        c->packets_out++;
        c->bytes_out += p->length;
    }
    if (p->protocol == FIREWALL_PROTO_TCP) update_tcp_state(c, p);
    return c->state == CONN_STATE_CLOSING ? CONN_STATE_ESTABLISHED : c->state;
}

static bool ip_in_ranges(ip_address_t ip, const ip_range_t* ranges, uint8_t count) {
    if (count == 0) return true;
    for (uint8_t i = 0; i < count; i++) {
        if ((ip.addr & ranges[i].netmask.addr) == (ranges[i].network.addr & ranges[i].netmask.addr)) {
            return true;
        }
    }
    return false;
}

static bool port_in_ranges(uint16_t port, const port_range_t* ranges, uint8_t count) {
    if (count == 0) return true;
    for (uint8_t i = 0; i < count; i++) {
        if (port >= ranges[i].start && port <= ranges[i].end) return true;
    }
    return false;
}

static bool rule_matches(const firewall_rule_t* r, const packet_info_t* p, connection_state_t state) {
    if (!r->enabled || !(r->direction & p->direction)) return false;
    if (r->protocol != FIREWALL_PROTO_ANY && r->protocol != p->protocol) return false;
    if (!ip_in_ranges(p->src_ip, r->src_ranges, r->src_range_count)) return false;
    if (!ip_in_ranges(p->dst_ip, r->dst_ranges, r->dst_range_count)) return false;
    if (!port_in_ranges(p->src_port, r->src_ports, r->src_port_count)) return false;
    if (!port_in_ranges(p->dst_port, r->dst_ports, r->dst_port_count)) return false;
    bool any_state = !r->match_new && !r->match_established && !r->match_related;
    if (any_state) return true;
    return (state == CONN_STATE_NEW && r->match_new) ||
           (state == CONN_STATE_ESTABLISHED && r->match_established) ||
           (state == CONN_STATE_RELATED && r->match_related);
}

static void log_match(const firewall_rule_t* r, const packet_info_t* p) {
    char src[16];
    char dst[16];
    ip_address_to_string(&p->src_ip, src);
    ip_address_to_string(&p->dst_ip, dst);
    terminal_write_string("FIREWALL: rule ");
    terminal_write_uint(r->rule_id);
    terminal_write_string(" ");
    terminal_write_string(action_name(r->action));
    terminal_write_string(" ");
    terminal_write_string(src);
    terminal_write_string(":");
    terminal_write_uint(p->src_port);
    terminal_write_string(" > ");
    terminal_write_string(dst);
    terminal_write_string(":");
    terminal_write_uint(p->dst_port);
    terminal_write_string("\n");
}

static void parse_packet(packet_info_t* p, firewall_direction_t dir, const ip_header_t* ip,
                         const void* payload, uint32_t length) {
    const uint8_t* bytes = (const uint8_t*)payload;
    zero_bytes(p, sizeof(*p));
    p->direction = dir;
    p->protocol = ip->protocol;
    p->src_ip = ip->source_ip;
    p->dst_ip = ip->dest_ip;
    p->length = length;
    if ((p->protocol == FIREWALL_PROTO_TCP || p->protocol == FIREWALL_PROTO_UDP) && length >= PORT_HEADER_BYTES) {
        p->src_port = (uint16_t)((bytes[0] << 8) | bytes[1]);
        p->dst_port = (uint16_t)((bytes[2] << 8) | bytes[3]);
    }
    if (p->protocol == FIREWALL_PROTO_TCP && length > TCP_FLAGS_OFFSET) {
        p->tcp_flags = bytes[TCP_FLAGS_OFFSET];
    }
}

// ICMP errors and replies that answer something we sent count as related traffic
static connection_state_t classify_icmp(const packet_info_t* p, const uint8_t* bytes, uint32_t length) {
    if (p->direction != FIREWALL_DIR_IN || length < 1) return CONN_STATE_NEW;
    uint8_t type = bytes[0];
    if (type == ICMP_ECHO_REPLY_TYPE || type == ICMP_UNREACHABLE_TYPE || type == ICMP_TIME_EXCEEDED_TYPE) {
        return CONN_STATE_RELATED;
    }
    return CONN_STATE_NEW;
}

firewall_action_t firewall_check_packet(firewall_direction_t direction, const ip_header_t* ip,
                                        const void* payload, uint32_t length) {
    if (!fw_enabled || !ip) return FIREWALL_ACTION_ALLOW;

    packet_info_t p;
    parse_packet(&p, direction, ip, payload, length);
    fw_stats.packets_processed++;
    fw_stats.bytes_processed += length;

    connection_state_t state = (p.protocol == FIREWALL_PROTO_ICMP)
        ? classify_icmp(&p, (const uint8_t*)payload, length)
        : track_packet(&p);

    firewall_action_t verdict = (direction == FIREWALL_DIR_IN) ? default_policy_in : default_policy_out;
    for (uint32_t i = 0; i < rule_count; i++) {
        firewall_rule_t* r = &rules[i];
        if (!rule_matches(r, &p, state)) continue;
        r->match_count++;
        r->byte_count += length;
        r->last_match_time = get_system_time();
        fw_stats.rule_matches++;
        if (r->log_matches || log_level >= LOG_LEVEL_MATCHES) log_match(r, &p);
        if (r->action == FIREWALL_ACTION_LOG) continue;
        verdict = r->action;
        break;
    }

    if (verdict == FIREWALL_ACTION_ALLOW) {
        fw_stats.packets_allowed++;
    } else if (verdict == FIREWALL_ACTION_DROP) {
        fw_stats.packets_dropped++;
    } else {
        fw_stats.packets_denied++;
    }
    return verdict;
}

static void add_default_rules(void) {
    firewall_rule_t r;
    zero_bytes(&r, sizeof(r));
    r.direction = FIREWALL_DIR_IN;
    r.protocol = FIREWALL_PROTO_ANY;
    r.match_established = true;
    r.match_related = true;
    r.action = FIREWALL_ACTION_ALLOW;
    string_copy(r.description, "Replies to outbound traffic");
    firewall_add_rule(&r);

    zero_bytes(&r, sizeof(r));
    r.direction = FIREWALL_DIR_IN;
    r.protocol = FIREWALL_PROTO_UDP;
    r.src_ports[0].start = DHCP_SERVER_PORT_NUMBER;
    r.src_ports[0].end = DHCP_SERVER_PORT_NUMBER;
    r.src_port_count = 1;
    r.dst_ports[0].start = DHCP_CLIENT_PORT_NUMBER;
    r.dst_ports[0].end = DHCP_CLIENT_PORT_NUMBER;
    r.dst_port_count = 1;
    r.action = FIREWALL_ACTION_ALLOW;
    string_copy(r.description, "DHCP offers and acks");
    firewall_add_rule(&r);
}

bool firewall_initialize(void) {
    if (fw_enabled) return true;
    zero_bytes(connections, sizeof(connections));
    fw_stats = (firewall_stats_t){0};
    fw_enabled = true;
    if (rule_count == 0) {
        add_default_rules();
    }
    terminal_write_string("FIREWALL: enabled, default policy IN ");
    terminal_write_string(action_name(default_policy_in));
    terminal_write_string(", OUT ");
    terminal_write_string(action_name(default_policy_out));
    terminal_write_string("\n");
    return true;
}

// Rules are kept so enabling again restores the same rule set
void firewall_shutdown(void) {
    fw_enabled = false;
    fw_stats.active_connections = 0;
    zero_bytes(connections, sizeof(connections));
    terminal_write_string("FIREWALL: disabled, all traffic passes\n");
}

bool firewall_is_enabled(void) {
    return fw_enabled;
}

uint32_t firewall_add_rule(const firewall_rule_t* rule) {
    if (!rule || rule_count >= FIREWALL_MAX_RULES) return 0;
    firewall_rule_t* slot = &rules[rule_count++];
    *slot = *rule;
    slot->rule_id = next_rule_id++;
    slot->enabled = true;
    slot->match_count = 0;
    slot->byte_count = 0;
    slot->last_match_time = 0;
    return slot->rule_id;
}

static int32_t find_rule_index(uint32_t rule_id) {
    for (uint32_t i = 0; i < rule_count; i++) {
        if (rules[i].rule_id == rule_id) return (int32_t)i;
    }
    return -1;
}

bool firewall_remove_rule(uint32_t rule_id) {
    int32_t index = find_rule_index(rule_id);
    if (index < 0) return false;
    for (uint32_t i = (uint32_t)index; i + 1 < rule_count; i++) {
        rules[i] = rules[i + 1];
    }
    rule_count--;
    return true;
}

bool firewall_enable_rule(uint32_t rule_id) {
    int32_t index = find_rule_index(rule_id);
    if (index < 0) return false;
    rules[index].enabled = true;
    return true;
}

bool firewall_disable_rule(uint32_t rule_id) {
    int32_t index = find_rule_index(rule_id);
    if (index < 0) return false;
    rules[index].enabled = false;
    return true;
}

bool firewall_get_rule(uint32_t rule_id, firewall_rule_t* rule) {
    int32_t index = find_rule_index(rule_id);
    if (index < 0 || !rule) return false;
    *rule = rules[index];
    return true;
}

bool firewall_get_rule_at(uint32_t index, firewall_rule_t* rule) {
    if (index >= rule_count || !rule) return false;
    *rule = rules[index];
    return true;
}

uint32_t firewall_get_rule_count(void) {
    return rule_count;
}

bool firewall_set_default_policy(firewall_direction_t direction, firewall_action_t action) {
    if (action == FIREWALL_ACTION_LOG) return false;
    if (direction & FIREWALL_DIR_IN) default_policy_in = action;
    if (direction & FIREWALL_DIR_OUT) default_policy_out = action;
    return true;
}

firewall_action_t firewall_get_default_policy(firewall_direction_t direction) {
    return (direction == FIREWALL_DIR_OUT) ? default_policy_out : default_policy_in;
}

void firewall_expire_connections(void) {
    uint32_t now = get_system_time();
    for (uint32_t i = 0; i < FIREWALL_MAX_CONNECTIONS; i++) {
        connection_entry_t* c = &connections[i];
        if (!c->is_active || now - c->last_activity < FIREWALL_CONNECTION_TIMEOUT) continue;
        if (connection_logging) {
            char dst[16];
            ip_address_to_string(&c->dst_ip, dst);
            terminal_write_string("FIREWALL: connection to ");
            terminal_write_string(dst);
            terminal_write_string(" expired\n");
        }
        c->is_active = false;
        fw_stats.connections_expired++;
        fw_stats.active_connections--;
    }
}

void firewall_process_timers(void) {
    static uint32_t last_run = 0;
    if (!fw_enabled) return;
    uint32_t now = get_system_time();
    if (now - last_run < FIREWALL_TIMER_INTERVAL_MS) return;
    last_run = now;
    firewall_expire_connections();
}

firewall_stats_t* firewall_get_statistics(void) {
    return fw_enabled ? &fw_stats : NULL;
}

void firewall_reset_statistics(void) {
    uint32_t active = fw_stats.active_connections;
    fw_stats = (firewall_stats_t){0};
    fw_stats.active_connections = active;
}

uint32_t firewall_get_active_connections(void) {
    return fw_stats.active_connections;
}

void firewall_set_log_level(uint8_t level) {
    log_level = level;
}

void firewall_enable_connection_logging(bool enable) {
    connection_logging = enable;
}

const char* firewall_action_name(firewall_action_t action) {
    return action_name(action);
}
#include "ip_stack.h"
#include "network_interface.h"
#include "tcp_stack.h"
#include "heap_allocator.h"
#include "time_keeper.h"
#include "terminal.h"
#include "firewall.h"
#include "rate_limiter.h"
#include "string_utils.h"
#include "types.h"

#define ICMP_CODE_ADMIN_PROHIBITED 13
#define ICMP_ERROR_PAYLOAD_BYTES 8
#define ICMP_EVENT_SLOTS 16
#define ICMP_ECHO_DATA 32
#define ARP_ATTEMPTS 3
#define ARP_WAIT_MS 1000
#define IP_FRAGMENT_MASK 0x3FFF
#define IP_DONT_FRAGMENT 0x4000
#define IPV4_BROADCAST 0xFFFFFFFFu
#define EPHEMERAL_PORT_BASE 49152
#define EPHEMERAL_PORT_RANGE 16384

static struct {
    arp_table_entry_t arp_table[ARP_TABLE_SIZE];
    udp_socket_t udp_sockets[UDP_MAX_PORTS];
    ip_route_t routes[IP_MAX_ROUTES];
    icmp_event_t icmp_events[ICMP_EVENT_SLOTS];
    bool icmp_event_used[ICMP_EVENT_SLOTS];
    uint32_t icmp_event_next;
    network_statistics_t stats;
    uint16_t next_ip_id;
    uint16_t next_ephemeral;
    bool is_initialized;
} ip_state;

static void zero_bytes(void* dest, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) d[i] = 0;
}

static void copy_bytes(void* dest, const void* src, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < size; i++) d[i] = s[i];
}

static uint32_t now_seconds(void) {
    return (uint32_t)time_keeper_get_uptime_seconds();
}

static uint16_t be16(uint16_t value) {
    return __builtin_bswap16(value);
}

void ip_stack_initialize(void) {
    if (ip_state.is_initialized) return;
    zero_bytes(&ip_state, sizeof(ip_state));
    ip_state.next_ip_id = 1;
    ip_state.next_ephemeral = (uint16_t)(get_system_time() % EPHEMERAL_PORT_RANGE);
    ip_state.is_initialized = true;
}

/* checksums */

uint16_t ip_calculate_checksum(const ip_header_t* header) {
    uint32_t length = (header->version_ihl & 0x0F) * 4u;
    uint8_t copy[60];
    copy_bytes(copy, header, length);
    copy[10] = 0;
    copy[11] = 0;
    return network_checksum(copy, length);
}

// Sums the IPv4 pseudo header the same way network_checksum sums data
uint32_t ip_pseudo_header_sum(const ip_address_t* source, const ip_address_t* dest, uint8_t protocol, uint16_t length) {
    uint8_t pseudo[12];
    copy_bytes(pseudo, &source->addr, 4);
    copy_bytes(pseudo + 4, &dest->addr, 4);
    pseudo[8] = 0;
    pseudo[9] = protocol;
    pseudo[10] = (uint8_t)(length >> 8);
    pseudo[11] = (uint8_t)length;
    uint32_t sum = 0;
    for (int i = 0; i < 12; i += 2) sum += (uint32_t)(pseudo[i] | (pseudo[i + 1] << 8));
    return sum;
}

uint16_t ip_finish_checksum(uint32_t sum, const void* data, uint32_t length) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return network_checksum_partial((uint16_t)sum, data, length);
}

/* routing */

static uint32_t prefix_length(const ip_address_t* mask) {
    return (uint32_t)__builtin_popcount(mask->addr);
}

static bool route_matches(const ip_route_t* r, const ip_address_t* dest) {
    return r->in_use && (dest->addr & r->netmask.addr) == (r->network.addr & r->netmask.addr);
}

// Static routes win by longest prefix, then connected subnets, then the first default gateway
bool ip_find_route(const ip_address_t* dest_ip, network_interface_t** out_interface, ip_address_t* next_hop) {
    const ip_route_t* best = NULL;
    for (uint32_t i = 0; i < IP_MAX_ROUTES; i++) {
        const ip_route_t* r = &ip_state.routes[i];
        if (route_matches(r, dest_ip) && r->iface && r->iface->state == NET_INTERFACE_UP &&
            (!best || prefix_length(&r->netmask) > prefix_length(&best->netmask))) {
            best = r;
        }
    }
    if (best) {
        *out_interface = best->iface;
        *next_hop = best->gateway.addr ? best->gateway : *dest_ip;
        return true;
    }
    network_interface_t* interfaces[NET_MAX_INTERFACES];
    uint32_t count = network_interface_list_all(interfaces, NET_MAX_INTERFACES);
    for (uint32_t i = 0; i < count; i++) {
        network_interface_t* iface = interfaces[i];
        if (iface->state == NET_INTERFACE_UP && iface->ip_addr.addr &&
            ip_address_is_in_subnet(dest_ip, &iface->ip_addr, &iface->netmask)) {
            *out_interface = iface;
            *next_hop = *dest_ip;
            return true;
        }
    }
    for (uint32_t i = 0; i < count; i++) {
        network_interface_t* iface = interfaces[i];
        if (iface->state == NET_INTERFACE_UP && iface->ip_addr.addr && iface->gateway.addr) {
            *out_interface = iface;
            *next_hop = iface->gateway;
            return true;
        }
    }
    return false;
}

bool ip_route_add(const ip_address_t* network, const ip_address_t* netmask, const ip_address_t* gateway,
                  network_interface_t* iface) {
    if (!network || !netmask || !iface) return false;
    ip_route_t* slot = NULL;
    for (uint32_t i = 0; i < IP_MAX_ROUTES; i++) {
        ip_route_t* r = &ip_state.routes[i];
        if (r->in_use && r->network.addr == (network->addr & netmask->addr) && r->netmask.addr == netmask->addr) {
            slot = r;
            break;
        }
        if (!r->in_use && !slot) slot = r;
    }
    if (!slot) return false;
    slot->network.addr = network->addr & netmask->addr;
    slot->netmask = *netmask;
    slot->gateway = gateway ? *gateway : (ip_address_t){0};
    slot->iface = iface;
    slot->in_use = true;
    return true;
}

bool ip_route_delete(const ip_address_t* network, const ip_address_t* netmask) {
    for (uint32_t i = 0; i < IP_MAX_ROUTES; i++) {
        ip_route_t* r = &ip_state.routes[i];
        if (r->in_use && r->network.addr == (network->addr & netmask->addr) && r->netmask.addr == netmask->addr) {
            r->in_use = false;
            return true;
        }
    }
    return false;
}

// Lists static routes followed by the connected and default routes derived from interfaces
uint32_t ip_route_list(ip_route_t* routes, uint32_t max_routes) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < IP_MAX_ROUTES && count < max_routes; i++) {
        if (ip_state.routes[i].in_use) routes[count++] = ip_state.routes[i];
    }
    network_interface_t* interfaces[NET_MAX_INTERFACES];
    uint32_t n = network_interface_list_all(interfaces, NET_MAX_INTERFACES);
    for (uint32_t i = 0; i < n && count < max_routes; i++) {
        network_interface_t* iface = interfaces[i];
        if (!iface->ip_addr.addr) continue;
        routes[count++] = (ip_route_t){{iface->ip_addr.addr & iface->netmask.addr}, iface->netmask, {0}, iface, false};
        if (iface->gateway.addr && count < max_routes) {
            routes[count++] = (ip_route_t){{0}, {0}, iface->gateway, iface, false};
        }
    }
    return count;
}

ip_address_t ip_source_for(const ip_address_t* dest_ip) {
    network_interface_t* iface = NULL;
    ip_address_t next_hop;
    if (ip_find_route(dest_ip, &iface, &next_hop)) return iface->ip_addr;
    network_interface_t* fallback = network_interface_get_default();
    return fallback ? fallback->ip_addr : (ip_address_t){0};
}

/* IPv4 output */

static bool resolve_destination(network_interface_t* iface, const ip_address_t* next_hop, mac_address_t* mac) {
    bool subnet_broadcast = iface->netmask.addr && iface->netmask.addr != IPV4_BROADCAST &&
                            (next_hop->addr | iface->netmask.addr) == IPV4_BROADCAST;
    if (next_hop->addr == IPV4_BROADCAST || subnet_broadcast) {
        for (int i = 0; i < NET_MAC_ADDR_LEN; i++) mac->addr[i] = 0xFF;
        return true;
    }
    return arp_resolve_ip(iface, next_hop, mac);
}

static bool transmit(network_interface_t* iface, const ip_address_t* next_hop, const ip_address_t* dest,
                     uint8_t protocol, uint8_t ttl, const void* payload, uint32_t length) {
    if (!iface || iface->state != NET_INTERFACE_UP || length > NET_MTU_SIZE - IP_HEADER_MIN_SIZE) return false;
    mac_address_t mac;
    if (!resolve_destination(iface, next_hop, &mac)) {
        ip_state.stats.ip_packets_dropped++;
        return false;
    }
    uint8_t packet[NET_MTU_SIZE];
    ip_header_t* h = (ip_header_t*)packet;
    h->version_ihl = (IP_VERSION_4 << 4) | (IP_HEADER_MIN_SIZE / 4);
    h->type_of_service = 0;
    h->total_length = be16((uint16_t)(IP_HEADER_MIN_SIZE + length));
    h->identification = be16(ip_state.next_ip_id++);
    h->flags_fragment = be16(IP_DONT_FRAGMENT);
    h->time_to_live = ttl;
    h->protocol = protocol;
    h->header_checksum = 0;
    h->source_ip = iface->ip_addr;
    h->dest_ip = *dest;
    h->header_checksum = network_checksum(packet, IP_HEADER_MIN_SIZE);
    copy_bytes(packet + IP_HEADER_MIN_SIZE, payload, length);

    if (firewall_check_packet(FIREWALL_DIR_OUT, h, payload, length) != FIREWALL_ACTION_ALLOW) {
        ip_state.stats.ip_packets_dropped++;
        return false;
    }
    if (!network_interface_send_ethernet_frame(iface, &mac, ETHERTYPE_IP, packet, IP_HEADER_MIN_SIZE + length)) {
        ip_state.stats.ip_packets_dropped++;
        return false;
    }
    ip_state.stats.ip_packets_sent++;
    return true;
}

// Limited broadcast leaves on the given interface, everything else follows the routing table
bool ip_send_packet(network_interface_t* iface, const ip_address_t* dest_ip,
                   uint8_t protocol, const void* payload, uint32_t payload_length) {
    if (!dest_ip || !payload || payload_length == 0) return false;
    if (dest_ip->addr == IPV4_BROADCAST || (iface && iface->ip_addr.addr == 0)) {
        network_interface_t* out = iface ? iface : network_interface_get_default();
        return transmit(out, dest_ip, dest_ip, protocol, IP_DEFAULT_TTL, payload, payload_length);
    }
    return ip_send_packet_ttl(dest_ip, protocol, IP_DEFAULT_TTL, payload, payload_length);
}

bool ip_send_packet_ttl(const ip_address_t* dest_ip, uint8_t protocol, uint8_t ttl,
                       const void* payload, uint32_t payload_length) {
    network_interface_t* iface = NULL;
    ip_address_t next_hop;
    if (!ip_find_route(dest_ip, &iface, &next_hop)) {
        ip_state.stats.ip_packets_dropped++;
        return false;
    }
    return transmit(iface, &next_hop, dest_ip, protocol, ttl, payload, payload_length);
}

bool ip_send_via_gateway(network_interface_t* iface, const ip_address_t* dest_ip,
                        const ip_address_t* gateway, uint8_t protocol,
                        const void* payload, uint32_t payload_length) {
    if (!iface || !dest_ip || !gateway) return false;
    return transmit(iface, gateway, dest_ip, protocol, IP_DEFAULT_TTL, payload, payload_length);
}

/* IPv4 input */

bool ip_is_packet_for_us(const ip_header_t* ip_header, network_interface_t* iface) {
    ip_address_t dest = ip_header->dest_ip;
    if (dest.addr == IPV4_BROADCAST || iface->ip_addr.addr == 0) return true;
    if (dest.addr == iface->ip_addr.addr) return true;
    return iface->netmask.addr && (dest.addr | iface->netmask.addr) == IPV4_BROADCAST;
}

static bool header_valid(const ip_header_t* h, uint32_t length, uint32_t* header_length, uint32_t* total_length) {
    if (length < IP_HEADER_MIN_SIZE || (h->version_ihl >> 4) != IP_VERSION_4) return false;
    *header_length = (h->version_ihl & 0x0F) * 4u;
    *total_length = be16(h->total_length);
    if (*header_length < IP_HEADER_MIN_SIZE || *header_length > length) return false;
    if (*total_length > length || *total_length < *header_length) return false;
    return network_checksum(h, *header_length) == 0;
}

void ip_process_packet(network_interface_t* iface, const void* packet, uint32_t length) {
    const ip_header_t* h = (const ip_header_t*)packet;
    uint32_t header_length, total_length;
    if (!iface || !packet || !header_valid(h, length, &header_length, &total_length)) {
        ip_state.stats.ip_packets_dropped++;
        return;
    }
    if (be16(h->flags_fragment) & IP_FRAGMENT_MASK & ~IP_DONT_FRAGMENT) {
        ip_state.stats.ip_fragments_dropped++;
        return;
    }
    if (!ip_is_packet_for_us(h, iface)) return;

    const uint8_t* payload = (const uint8_t*)packet + header_length;
    uint32_t payload_length = total_length - header_length;
    firewall_action_t verdict = firewall_check_packet(FIREWALL_DIR_IN, h, payload, payload_length);
    if (verdict != FIREWALL_ACTION_ALLOW || !rate_limiter_check_packet(h, payload, payload_length)) {
        if (verdict == FIREWALL_ACTION_REJECT) {
            ip_address_t source = h->source_ip;
            icmp_send_dest_unreachable(iface, &source, ICMP_CODE_ADMIN_PROHIBITED, h);
        }
        ip_state.stats.ip_packets_dropped++;
        return;
    }
    ip_state.stats.ip_packets_received++;

    switch (h->protocol) {
        case IP_PROTOCOL_ICMP: icmp_process_packet(iface, h, payload, payload_length); break;
        case IP_PROTOCOL_UDP: udp_process_packet(iface, h, payload, payload_length); break;
        case IP_PROTOCOL_TCP: tcp_process_packet(iface, h, payload, payload_length); break;
        default: ip_state.stats.ip_packets_dropped++; break;
    }
}

/* ARP */

void arp_initialize(void) {
    arp_clear_table();
}

void arp_clear_table(void) {
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; i++) ip_state.arp_table[i].is_valid = false;
}

arp_table_entry_t* arp_find_entry(const ip_address_t* ip_addr) {
    if (!ip_addr) return NULL;
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; i++) {
        arp_table_entry_t* e = &ip_state.arp_table[i];
        if (e->is_valid && e->ip_addr.addr == ip_addr->addr) return e;
    }
    return NULL;
}

void arp_add_entry(const ip_address_t* ip_addr, const mac_address_t* mac_addr) {
    if (!ip_addr || !mac_addr || ip_addr->addr == 0) return;
    arp_table_entry_t* slot = arp_find_entry(ip_addr);
    arp_table_entry_t* oldest = &ip_state.arp_table[0];
    for (uint32_t i = 0; i < ARP_TABLE_SIZE && !slot; i++) {
        arp_table_entry_t* e = &ip_state.arp_table[i];
        if (!e->is_valid) slot = e;
        else if (e->timestamp < oldest->timestamp) oldest = e;
    }
    if (!slot) slot = oldest;
    slot->ip_addr = *ip_addr;
    mac_address_copy(&slot->mac_addr, mac_addr);
    slot->timestamp = now_seconds();
    slot->is_valid = true;
}

static void send_arp(network_interface_t* iface, uint16_t operation, const ip_address_t* target_ip,
                     const mac_address_t* target_mac, const mac_address_t* frame_dest) {
    arp_header_t arp;
    arp.hardware_type = be16(ARP_HARDWARE_ETHERNET);
    arp.protocol_type = be16(ARP_PROTOCOL_IPV4);
    arp.hardware_length = NET_MAC_ADDR_LEN;
    arp.protocol_length = 4;
    arp.operation = be16(operation);
    arp.sender_mac = iface->mac_addr;
    arp.sender_ip = iface->ip_addr;
    arp.target_mac = *target_mac;
    arp.target_ip = *target_ip;
    network_interface_send_ethernet_frame(iface, frame_dest, ETHERTYPE_ARP, &arp, sizeof(arp));
}

void arp_send_request(network_interface_t* iface, const ip_address_t* target_ip) {
    if (!iface || !target_ip || iface->state != NET_INTERFACE_UP) return;
    mac_address_t zero = {{0}};
    mac_address_t broadcast = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    send_arp(iface, ARP_OPERATION_REQUEST, target_ip, &zero, &broadcast);
    ip_state.stats.arp_requests_sent++;
}

void arp_send_reply(network_interface_t* iface, const ip_address_t* target_ip, const mac_address_t* target_mac) {
    if (!iface || !target_ip || !target_mac) return;
    send_arp(iface, ARP_OPERATION_REPLY, target_ip, target_mac, target_mac);
    ip_state.stats.arp_replies_sent++;
}

static bool arp_cached(const ip_address_t* ip_addr, mac_address_t* mac_addr) {
    arp_table_entry_t* e = arp_find_entry(ip_addr);
    if (!e || now_seconds() - e->timestamp >= ARP_ENTRY_TIMEOUT) return false;
    mac_address_copy(mac_addr, &e->mac_addr);
    return true;
}

// Only drains received frames while waiting, so a reply can arrive without timers sending more traffic
bool arp_resolve_ip(network_interface_t* iface, const ip_address_t* ip_addr, mac_address_t* mac_addr) {
    if (!iface || !ip_addr || !mac_addr || iface->state != NET_INTERFACE_UP) return false;
    if (arp_cached(ip_addr, mac_addr)) return true;
    for (int attempt = 0; attempt < ARP_ATTEMPTS; attempt++) {
        arp_send_request(iface, ip_addr);
        uint32_t deadline = get_system_time() + ARP_WAIT_MS;
        while (get_system_time() < deadline) {
            network_interface_process_incoming_packets();
            if (arp_cached(ip_addr, mac_addr)) return true;
        }
    }
    return false;
}

void arp_process_packet(network_interface_t* iface, const void* packet, uint32_t length) {
    if (!iface || !packet || length < sizeof(arp_header_t)) return;
    const arp_header_t* arp = (const arp_header_t*)packet;
    if (be16(arp->hardware_type) != ARP_HARDWARE_ETHERNET || be16(arp->protocol_type) != ARP_PROTOCOL_IPV4 ||
        arp->hardware_length != NET_MAC_ADDR_LEN || arp->protocol_length != 4) {
        return;
    }
    ip_address_t sender_ip = arp->sender_ip;
    ip_address_t target_ip = arp->target_ip;
    mac_address_t sender_mac = arp->sender_mac;
    arp_add_entry(&sender_ip, &sender_mac);

    uint16_t operation = be16(arp->operation);
    if (operation == ARP_OPERATION_REQUEST) {
        ip_state.stats.arp_requests_received++;
        if (iface->ip_addr.addr && target_ip.addr == iface->ip_addr.addr) {
            arp_send_reply(iface, &sender_ip, &sender_mac);
        }
    } else if (operation == ARP_OPERATION_REPLY) {
        ip_state.stats.arp_replies_received++;
    }
}

void arp_update_table(void) {
    uint32_t now = now_seconds();
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; i++) {
        arp_table_entry_t* e = &ip_state.arp_table[i];
        if (e->is_valid && now - e->timestamp >= ARP_ENTRY_TIMEOUT) e->is_valid = false;
    }
}

void arp_dump_table(void) {
    terminal_write_string("IP Address      MAC Address         Age\n");
    uint32_t now = now_seconds();
    uint32_t shown = 0;
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; i++) {
        arp_table_entry_t* e = &ip_state.arp_table[i];
        if (!e->is_valid) continue;
        char ip_str[16];
        char mac_str[18];
        ip_address_to_string(&e->ip_addr, ip_str);
        mac_address_to_string(&e->mac_addr, mac_str);
        terminal_write_string(ip_str);
        for (uint32_t j = string_length(ip_str); j < 16; j++) terminal_write_char(' ');
        terminal_write_string(mac_str);
        terminal_write_string("   ");
        terminal_write_uint(now - e->timestamp);
        terminal_write_string("s\n");
        shown++;
    }
    if (shown == 0) terminal_write_string("(empty)\n");
}

/* ICMP */

void icmp_initialize(void) {
    for (uint32_t i = 0; i < ICMP_EVENT_SLOTS; i++) ip_state.icmp_event_used[i] = false;
}

static bool send_icmp(const ip_address_t* dest, uint8_t ttl, uint8_t type, uint8_t code,
                      uint16_t identifier, uint16_t sequence, const void* data, uint32_t data_length,
                      network_interface_t* iface) {
    uint8_t buffer[NET_MTU_SIZE - IP_HEADER_MIN_SIZE];
    uint32_t length = sizeof(icmp_header_t) + data_length;
    if (length > sizeof(buffer)) return false;
    icmp_header_t* icmp = (icmp_header_t*)buffer;
    icmp->type = type;
    icmp->code = code;
    icmp->checksum = 0;
    icmp->identifier = be16(identifier);
    icmp->sequence = be16(sequence);
    if (data_length) copy_bytes(buffer + sizeof(icmp_header_t), data, data_length);
    icmp->checksum = network_checksum(buffer, length);
    bool ok = iface ? ip_send_packet(iface, dest, IP_PROTOCOL_ICMP, buffer, length)
                    : ip_send_packet_ttl(dest, IP_PROTOCOL_ICMP, ttl, buffer, length);
    if (ok) ip_state.stats.icmp_packets_sent++;
    return ok;
}

bool icmp_send_echo_request(network_interface_t* iface, const ip_address_t* dest_ip,
                           uint16_t identifier, uint16_t sequence, const void* data, uint16_t data_length) {
    return send_icmp(dest_ip, IP_DEFAULT_TTL, ICMP_TYPE_ECHO_REQUEST, 0, identifier, sequence, data, data_length, iface);
}

bool icmp_send_echo_ttl(const ip_address_t* dest_ip, uint8_t ttl, uint16_t identifier, uint16_t sequence) {
    uint8_t data[ICMP_ECHO_DATA];
    for (uint32_t i = 0; i < ICMP_ECHO_DATA; i++) data[i] = (uint8_t)('a' + i % 26);
    return send_icmp(dest_ip, ttl, ICMP_TYPE_ECHO_REQUEST, 0, identifier, sequence, data, ICMP_ECHO_DATA, NULL);
}

bool icmp_send_echo_reply(network_interface_t* iface, const ip_address_t* dest_ip,
                         uint16_t identifier, uint16_t sequence, const void* data, uint16_t data_length) {
    return send_icmp(dest_ip, IP_DEFAULT_TTL, ICMP_TYPE_ECHO_REPLY, 0, identifier, sequence, data, data_length, iface);
}

// Quotes the offending IP header and the first 8 payload bytes as RFC 792 requires
void icmp_send_dest_unreachable(network_interface_t* iface, const ip_address_t* dest_ip,
                               uint8_t code, const ip_header_t* original_packet) {
    if (!iface || !dest_ip || !original_packet) return;
    uint32_t quoted = (original_packet->version_ihl & 0x0F) * 4u + ICMP_ERROR_PAYLOAD_BYTES;
    send_icmp(dest_ip, IP_DEFAULT_TTL, ICMP_TYPE_DEST_UNREACHABLE, code, 0, 0, original_packet, quoted, iface);
}

static void record_event(uint8_t type, uint8_t code, const ip_address_t* from, uint16_t identifier, uint16_t sequence) {
    uint32_t slot = ip_state.icmp_event_next++ % ICMP_EVENT_SLOTS;
    ip_state.icmp_events[slot] = (icmp_event_t){type, code, *from, identifier, sequence, get_system_time()};
    ip_state.icmp_event_used[slot] = true;
}

// Errors quote our original echo request, which carries the identifier and sequence to match
static void record_error(const icmp_header_t* icmp, const uint8_t* body, uint32_t length, const ip_address_t* from) {
    if (length < IP_HEADER_MIN_SIZE) return;
    const ip_header_t* inner = (const ip_header_t*)body;
    uint32_t inner_length = (inner->version_ihl & 0x0F) * 4u;
    if (inner->protocol != IP_PROTOCOL_ICMP || length < inner_length + sizeof(icmp_header_t)) {
        record_event(icmp->type, icmp->code, from, 0, 0);
        return;
    }
    const icmp_header_t* echo = (const icmp_header_t*)(body + inner_length);
    record_event(icmp->type, icmp->code, from, be16(echo->identifier), be16(echo->sequence));
}

void icmp_process_packet(network_interface_t* iface, const ip_header_t* ip_header,
                        const void* icmp_packet, uint32_t length) {
    if (length < sizeof(icmp_header_t) || network_checksum(icmp_packet, length) != 0) return;
    const icmp_header_t* icmp = (const icmp_header_t*)icmp_packet;
    const uint8_t* body = (const uint8_t*)icmp_packet + sizeof(icmp_header_t);
    uint32_t body_length = length - sizeof(icmp_header_t);
    ip_address_t source = ip_header->source_ip;
    ip_state.stats.icmp_packets_received++;

    switch (icmp->type) {
        case ICMP_TYPE_ECHO_REQUEST:
            icmp_send_echo_reply(iface, &source, be16(icmp->identifier), be16(icmp->sequence), body, (uint16_t)body_length);
            break;
        case ICMP_TYPE_ECHO_REPLY:
            record_event(icmp->type, icmp->code, &source, be16(icmp->identifier), be16(icmp->sequence));
            break;
        case ICMP_TYPE_DEST_UNREACHABLE:
        case ICMP_TYPE_TIME_EXCEEDED:
            record_error(icmp, body, body_length, &source);
            break;
    }
}

bool icmp_wait_event(uint16_t identifier, uint16_t sequence, uint32_t timeout_ms, icmp_event_t* event) {
    uint32_t deadline = get_system_time() + timeout_ms;
    do {
        network_interface_process_incoming_packets();
        for (uint32_t i = 0; i < ICMP_EVENT_SLOTS; i++) {
            icmp_event_t* e = &ip_state.icmp_events[i];
            if (ip_state.icmp_event_used[i] && e->identifier == identifier && e->sequence == sequence) {
                ip_state.icmp_event_used[i] = false;
                *event = *e;
                return true;
            }
        }
    } while (get_system_time() < deadline);
    return false;
}

/* UDP */

void udp_initialize(void) {
    for (uint32_t i = 0; i < UDP_MAX_PORTS; i++) {
        if (ip_state.udp_sockets[i].is_bound) udp_close_socket(&ip_state.udp_sockets[i]);
    }
}

udp_socket_t* udp_create_socket(void) {
    for (uint32_t i = 0; i < UDP_MAX_PORTS; i++) {
        udp_socket_t* s = &ip_state.udp_sockets[i];
        if (!s->is_bound && !s->queue) {
            zero_bytes(s, sizeof(*s));
            return s;
        }
    }
    return NULL;
}

static bool port_in_use(uint16_t port) {
    for (uint32_t i = 0; i < UDP_MAX_PORTS; i++) {
        if (ip_state.udp_sockets[i].is_bound && ip_state.udp_sockets[i].local_port == port) return true;
    }
    return false;
}

bool udp_bind_socket(udp_socket_t* socket, uint16_t port) {
    if (!socket || socket->is_bound) return false;
    if (port == 0) {
        for (uint32_t tries = 0; tries < EPHEMERAL_PORT_RANGE && port == 0; tries++) {
            uint16_t candidate = (uint16_t)(EPHEMERAL_PORT_BASE + ip_state.next_ephemeral++ % EPHEMERAL_PORT_RANGE);
            if (!port_in_use(candidate)) port = candidate;
        }
    }
    if (port == 0 || port_in_use(port)) return false;
    socket->queue = apollo_allocate_memory(sizeof(udp_datagram_t) * UDP_QUEUE_DEPTH);
    if (!socket->queue) return false;
    socket->local_port = port;
    socket->is_bound = true;
    return true;
}

bool udp_connect_socket(udp_socket_t* socket, const ip_address_t* remote_ip, uint16_t remote_port) {
    if (!socket || !remote_ip || remote_port == 0) return false;
    if (!socket->is_bound && !udp_bind_socket(socket, 0)) return false;
    socket->remote_ip = *remote_ip;
    socket->remote_port = remote_port;
    socket->is_connected = true;
    return true;
}

static bool udp_output(udp_socket_t* socket, network_interface_t* iface, const ip_address_t* dest_ip,
                       uint16_t dest_port, const void* data, uint32_t length) {
    if (!socket || !dest_ip || (!data && length) || length > UDP_MAX_DATAGRAM) return false;
    if (!socket->is_bound && !udp_bind_socket(socket, 0)) return false;
    uint8_t buffer[UDP_HEADER_SIZE + UDP_MAX_DATAGRAM];
    udp_header_t* udp = (udp_header_t*)buffer;
    uint16_t total = (uint16_t)(UDP_HEADER_SIZE + length);
    udp->source_port = be16(socket->local_port);
    udp->dest_port = be16(dest_port);
    udp->length = be16(total);
    udp->checksum = 0;
    if (length) copy_bytes(buffer + UDP_HEADER_SIZE, data, length);
    ip_address_t source = iface ? iface->ip_addr : ip_source_for(dest_ip);
    uint16_t checksum = ip_finish_checksum(ip_pseudo_header_sum(&source, dest_ip, IP_PROTOCOL_UDP, total), buffer, total);
    udp->checksum = checksum ? checksum : 0xFFFF;
    bool ok = ip_send_packet(iface, dest_ip, IP_PROTOCOL_UDP, buffer, total);
    if (ok) ip_state.stats.udp_packets_sent++;
    return ok;
}

// Broadcasts leave on the default interface, unicast is routed
bool udp_send_to(udp_socket_t* socket, const ip_address_t* dest_ip, uint16_t dest_port,
                 const void* data, uint32_t length) {
    network_interface_t* iface = dest_ip && dest_ip->addr == IPV4_BROADCAST ? network_interface_get_default() : NULL;
    return udp_output(socket, iface, dest_ip, dest_port, data, length);
}

bool udp_send_data(udp_socket_t* socket, const void* data, uint32_t length) {
    if (!socket || !socket->is_connected) return false;
    return udp_output(socket, NULL, &socket->remote_ip, socket->remote_port, data, length);
}

int32_t udp_receive_data(udp_socket_t* socket, void* buffer, uint32_t buffer_size,
                        ip_address_t* sender_ip, uint16_t* sender_port) {
    if (!socket || !socket->queue || !buffer) return -1;
    if (socket->queue_tail == socket->queue_head) return 0;
    udp_datagram_t* d = &socket->queue[socket->queue_tail];
    uint32_t length = d->length < buffer_size ? d->length : buffer_size;
    copy_bytes(buffer, d->data, length);
    if (sender_ip) *sender_ip = d->source;
    if (sender_port) *sender_port = d->port;
    socket->queue_tail = (socket->queue_tail + 1) % UDP_QUEUE_DEPTH;
    return (int32_t)length;
}

void udp_close_socket(udp_socket_t* socket) {
    if (!socket) return;
    if (socket->queue) apollo_free_memory(socket->queue);
    zero_bytes(socket, sizeof(*socket));
}

uint32_t udp_list_bound_ports(uint16_t* ports, uint32_t max_ports) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < UDP_MAX_PORTS && count < max_ports; i++) {
        if (ip_state.udp_sockets[i].is_bound) ports[count++] = ip_state.udp_sockets[i].local_port;
    }
    return count;
}

static udp_socket_t* find_udp_socket(uint16_t port, const ip_address_t* source, uint16_t source_port) {
    for (uint32_t i = 0; i < UDP_MAX_PORTS; i++) {
        udp_socket_t* s = &ip_state.udp_sockets[i];
        if (!s->is_bound || s->local_port != port) continue;
        if (s->is_connected && (s->remote_ip.addr != source->addr || s->remote_port != source_port)) continue;
        return s;
    }
    return NULL;
}

static void enqueue(udp_socket_t* s, const ip_address_t* source, uint16_t port, const uint8_t* data, uint32_t length) {
    uint32_t next = (s->queue_head + 1) % UDP_QUEUE_DEPTH;
    if (next == s->queue_tail) {
        s->dropped++;
        return;
    }
    udp_datagram_t* d = &s->queue[s->queue_head];
    d->source = *source;
    d->port = port;
    d->length = (uint16_t)length;
    copy_bytes(d->data, data, length);
    s->queue_head = next;
}

void udp_process_packet(network_interface_t* iface, const ip_header_t* ip_header,
                       const void* udp_packet, uint32_t length) {
    if (length < UDP_HEADER_SIZE) return;
    const udp_header_t* udp = (const udp_header_t*)udp_packet;
    uint16_t udp_length = be16(udp->length);
    if (udp_length > length || udp_length < UDP_HEADER_SIZE) return;
    ip_address_t source = ip_header->source_ip;
    ip_address_t dest = ip_header->dest_ip;
    if (udp->checksum && ip_finish_checksum(ip_pseudo_header_sum(&source, &dest, IP_PROTOCOL_UDP, udp_length),
                                            udp_packet, udp_length) != 0) {
        ip_state.stats.ip_packets_dropped++;
        return;
    }
    ip_state.stats.udp_packets_received++;

    uint16_t dest_port = be16(udp->dest_port);
    uint16_t source_port = be16(udp->source_port);
    const uint8_t* data = (const uint8_t*)udp_packet + UDP_HEADER_SIZE;
    uint32_t data_length = udp_length - UDP_HEADER_SIZE;
    udp_socket_t* s = find_udp_socket(dest_port, &source, source_port);
    if (!s) {
        ip_state.stats.udp_no_port++;
        if (iface->ip_addr.addr && dest.addr == iface->ip_addr.addr) {
            icmp_send_dest_unreachable(iface, &source, ICMP_CODE_PORT_UNREACHABLE, ip_header);
        }
        return;
    }
    if (s->receive_callback) s->receive_callback(dest_port, &source, data, data_length);
    else enqueue(s, &source, source_port, data, data_length > UDP_MAX_DATAGRAM ? UDP_MAX_DATAGRAM : data_length);
}

void udp_set_receive_callback(udp_socket_t* socket,
    void (*callback)(uint16_t port, const ip_address_t* remote_ip, const void* data, uint32_t length)) {
    if (socket) socket->receive_callback = callback;
}

void network_process_incoming_packets(void) {
    network_interface_process_incoming_packets();
}

void network_periodic_tasks(void) {
    arp_update_table();
}

network_statistics_t* network_get_statistics(void) {
    return &ip_state.stats;
}

void network_reset_statistics(void) {
    zero_bytes(&ip_state.stats, sizeof(ip_state.stats));
}
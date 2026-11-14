#include "dhcp_client.h"
#include "dns_client.h"
#include "network_interface.h"
#include "ip_stack.h"
#include "heap_allocator.h"
#include "time_keeper.h"
#include "terminal.h"
#include "string_utils.h"
#include "types.h"

#define DHCP_RETRY_MS 4000
#define DHCP_MAX_TRIES 4
#define DHCP_RESTART_MS 10000
#define DHCP_FLAG_BROADCAST 0x8000
#define DHCP_HLEN_ETHERNET 6
#define DHCP_FIXED_SIZE 240     // BOOTP header plus the magic cookie
#define DHCP_OPTION_PAD 0
#define DHCP_DEFAULT_LEASE 3600
#define DHCP_MAX_PACKET 576
#define IPV4_BROADCAST 0xFFFFFFFFu

static struct {
    dhcp_client_t* clients[NET_MAX_INTERFACES];
    udp_socket_t* socket;
    dhcp_statistics_t stats;
    uint32_t seed;
    bool is_initialized;
} dhcp_state = {0};

static void zero_bytes(void* dest, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) d[i] = 0;
}

static void copy_bytes(void* dest, const void* src, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < size; i++) d[i] = s[i];
}

static uint32_t now_ms(void) {
    return get_system_time();
}

static uint32_t now_seconds(void) {
    return (uint32_t)time_keeper_get_uptime_seconds();
}

static void receive_callback(uint16_t port, const ip_address_t* remote_ip, const void* data, uint32_t length);

bool dhcp_client_initialize(void) {
    if (dhcp_state.is_initialized) return true;
    dhcp_state.socket = udp_create_socket();
    if (!dhcp_state.socket || !udp_bind_socket(dhcp_state.socket, DHCP_CLIENT_PORT)) return false;
    udp_set_receive_callback(dhcp_state.socket, receive_callback);
    dhcp_state.seed = (uint32_t)time_keeper_get_unix_time() ^ now_ms();
    dhcp_state.is_initialized = true;
    return true;
}

uint32_t dhcp_generate_transaction_id(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    dhcp_state.seed = dhcp_state.seed * 1103515245u + 12345u + lo;
    return dhcp_state.seed ^ hi;
}

dhcp_client_t* dhcp_client_create(network_interface_t* interface) {
    if (!interface || !dhcp_client_initialize()) return NULL;
    dhcp_client_t* client = apollo_allocate_memory(sizeof(dhcp_client_t));
    if (!client) return NULL;
    zero_bytes(client, sizeof(dhcp_client_t));
    client->interface = interface;
    client->state = DHCP_STATE_INIT;
    client->socket = dhcp_state.socket;
    client->auto_renew = true;
    string_copy(client->hostname, "apollo");
    static const uint8_t defaults[] = {DHCP_OPTION_SUBNET_MASK, DHCP_OPTION_ROUTER, DHCP_OPTION_DNS_SERVER,
                                       DHCP_OPTION_BROADCAST_ADDRESS, DHCP_OPTION_LEASE_TIME};
    for (uint32_t i = 0; i < sizeof(defaults); i++) dhcp_client_add_requested_option(client, defaults[i]);
    return client;
}

void dhcp_client_destroy(dhcp_client_t* client) {
    if (!client) return;
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        if (dhcp_state.clients[i] == client) dhcp_state.clients[i] = NULL;
    }
    apollo_free_memory(client);
}

/* packet building */

static void put_option(uint8_t* options, uint32_t* offset, uint8_t type, const void* data, uint8_t length) {
    options[(*offset)++] = type;
    options[(*offset)++] = length;
    copy_bytes(options + *offset, data, length);
    *offset += length;
}

uint32_t dhcp_build_options(uint8_t* options_buffer, uint8_t message_type,
                           const dhcp_client_t* client, const ip_address_t* requested_ip,
                           const ip_address_t* server_ip) {
    if (!options_buffer || !client) return 0;
    uint32_t offset = 0;
    put_option(options_buffer, &offset, DHCP_OPTION_MESSAGE_TYPE, &message_type, 1);
    if (client->client_identifier[0]) {
        put_option(options_buffer, &offset, DHCP_OPTION_CLIENT_IDENTIFIER, client->client_identifier,
                   (uint8_t)string_length(client->client_identifier));
    } else {
        uint8_t id[1 + DHCP_HLEN_ETHERNET] = {DHCP_HARDWARE_ETHERNET};
        copy_bytes(id + 1, client->interface->mac_addr.addr, DHCP_HLEN_ETHERNET);
        put_option(options_buffer, &offset, DHCP_OPTION_CLIENT_IDENTIFIER, id, sizeof(id));
    }
    if (client->hostname[0]) {
        put_option(options_buffer, &offset, DHCP_OPTION_HOST_NAME, client->hostname, (uint8_t)string_length(client->hostname));
    }
    if (requested_ip && requested_ip->addr) put_option(options_buffer, &offset, DHCP_OPTION_REQUESTED_IP, &requested_ip->addr, 4);
    if (server_ip && server_ip->addr) put_option(options_buffer, &offset, DHCP_OPTION_SERVER_IDENTIFIER, &server_ip->addr, 4);
    if (client->num_requested_options) {
        put_option(options_buffer, &offset, DHCP_OPTION_PARAMETER_REQUEST_LIST, client->requested_options,
                   client->num_requested_options);
    }
    options_buffer[offset++] = DHCP_OPTION_END;
    return offset;
}

// Requested and server options are only included where RFC 2131 table 5 asks for them
static bool send_message(dhcp_client_t* client, uint8_t type, const ip_address_t* requested,
                         const ip_address_t* server, const ip_address_t* dest, bool use_ciaddr) {
    uint8_t packet[DHCP_MAX_PACKET];
    zero_bytes(packet, sizeof(packet));
    dhcp_header_t* h = (dhcp_header_t*)packet;
    h->op = DHCP_BOOTREQUEST;
    h->htype = DHCP_HARDWARE_ETHERNET;
    h->hlen = DHCP_HLEN_ETHERNET;
    h->xid = __builtin_bswap32(client->transaction_id);
    h->secs = __builtin_bswap16((uint16_t)((now_ms() - client->discover_start_time) / 1000));
    h->flags = use_ciaddr ? 0 : __builtin_bswap16(DHCP_FLAG_BROADCAST);
    if (use_ciaddr) h->ciaddr = client->lease.assigned_ip;
    copy_bytes(h->chaddr, client->interface->mac_addr.addr, DHCP_HLEN_ETHERNET);
    h->magic_cookie = __builtin_bswap32(DHCP_MAGIC_COOKIE);
    uint32_t length = DHCP_FIXED_SIZE + dhcp_build_options(packet + DHCP_FIXED_SIZE, type, client, requested, server);
    if (length < DHCP_PACKET_MIN_SIZE) length = DHCP_PACKET_MIN_SIZE;

    if (dest->addr == IPV4_BROADCAST) {
        network_interface_t* iface = client->interface;
        ip_address_t saved = iface->ip_addr;
        if (!use_ciaddr) iface->ip_addr.addr = 0;
        bool ok = udp_send_to(client->socket, dest, DHCP_SERVER_PORT, packet, length);
        iface->ip_addr = saved;
        return ok;
    }
    return udp_send_to(client->socket, dest, DHCP_SERVER_PORT, packet, length);
}

static void set_timeout(dhcp_client_t* client, uint32_t delay_ms) {
    client->next_timeout = now_ms() + delay_ms;
}

bool dhcp_send_discover(dhcp_client_t* client) {
    if (!client) return false;
    ip_address_t broadcast = {IPV4_BROADCAST};
    client->state = DHCP_STATE_SELECTING;
    set_timeout(client, DHCP_RETRY_MS);
    dhcp_state.stats.discovers_sent++;
    return send_message(client, DHCP_DISCOVER, NULL, NULL, &broadcast, false);
}

bool dhcp_send_request(dhcp_client_t* client, const ip_address_t* server_ip, const ip_address_t* requested_ip) {
    if (!client) return false;
    ip_address_t broadcast = {IPV4_BROADCAST};
    set_timeout(client, DHCP_RETRY_MS);
    dhcp_state.stats.requests_sent++;
    if (client->state == DHCP_STATE_RENEWING) {
        return send_message(client, DHCP_REQUEST, NULL, NULL, server_ip, true);
    }
    if (client->state == DHCP_STATE_REBINDING) {
        return send_message(client, DHCP_REQUEST, NULL, NULL, &broadcast, true);
    }
    client->state = DHCP_STATE_REQUESTING;
    return send_message(client, DHCP_REQUEST, requested_ip, server_ip, &broadcast, false);
}

bool dhcp_send_release(dhcp_client_t* client) {
    if (!client || !client->lease.is_valid) return false;
    dhcp_state.stats.releases_sent++;
    client->transaction_id = dhcp_generate_transaction_id();
    return send_message(client, DHCP_RELEASE, NULL, &client->lease.dhcp_server, &client->lease.dhcp_server, true);
}

/* packet parsing */

uint8_t* dhcp_find_option(const dhcp_header_t* header, uint32_t packet_length, uint8_t option_type) {
    if (!header || packet_length <= DHCP_FIXED_SIZE) return NULL;
    uint8_t* options = (uint8_t*)header + DHCP_FIXED_SIZE;
    uint32_t limit = packet_length - DHCP_FIXED_SIZE;
    for (uint32_t i = 0; i < limit;) {
        uint8_t type = options[i];
        if (type == DHCP_OPTION_END) break;
        if (type == DHCP_OPTION_PAD) { i++; continue; }
        if (i + 1 >= limit || i + 2 + options[i + 1] > limit) break;
        if (type == option_type) return &options[i];
        i += 2 + options[i + 1];
    }
    return NULL;
}

static bool read_address(const dhcp_header_t* h, uint32_t length, uint8_t type, ip_address_t* out) {
    uint8_t* option = dhcp_find_option(h, length, type);
    if (!option || option[1] < 4) return false;
    copy_bytes(&out->addr, &option[2], 4);
    return true;
}

static bool read_seconds(const dhcp_header_t* h, uint32_t length, uint8_t type, uint32_t* out) {
    uint8_t* option = dhcp_find_option(h, length, type);
    if (!option || option[1] != 4) return false;
    *out = ((uint32_t)option[2] << 24) | ((uint32_t)option[3] << 16) | ((uint32_t)option[4] << 8) | option[5];
    return true;
}

// Missing T1 and T2 fall back to half and seven eighths of the lease as RFC 2131 suggests
bool dhcp_parse_options(const dhcp_header_t* header, uint32_t packet_length, dhcp_lease_info_t* lease) {
    if (!header || !lease || packet_length <= DHCP_FIXED_SIZE) return false;
    read_address(header, packet_length, DHCP_OPTION_SUBNET_MASK, &lease->subnet_mask);
    read_address(header, packet_length, DHCP_OPTION_ROUTER, &lease->gateway);
    read_address(header, packet_length, DHCP_OPTION_DNS_SERVER, &lease->dns_server);
    read_address(header, packet_length, DHCP_OPTION_SERVER_IDENTIFIER, &lease->dhcp_server);
    if (!read_seconds(header, packet_length, DHCP_OPTION_LEASE_TIME, &lease->lease_time)) lease->lease_time = DHCP_DEFAULT_LEASE;
    if (!read_seconds(header, packet_length, DHCP_OPTION_RENEWAL_TIME, &lease->renewal_time)) lease->renewal_time = lease->lease_time / 2;
    if (!read_seconds(header, packet_length, DHCP_OPTION_REBINDING_TIME, &lease->rebinding_time)) {
        lease->rebinding_time = lease->lease_time / 8 * 7;
    }
    return true;
}

void dhcp_client_apply_lease(dhcp_client_t* client) {
    if (!client || !client->lease.is_valid) return;
    network_interface_set_ip_config(client->interface->interface_id, client->lease.assigned_ip,
                                    client->lease.subnet_mask, client->lease.gateway);
    network_interface_bring_up(client->interface->interface_id);
    if (client->lease.dns_server.addr) dns_configure_from_dhcp(&client->lease.dns_server, 1);
}

static void on_offer(dhcp_client_t* client, const dhcp_header_t* h, uint32_t length) {
    if (client->state != DHCP_STATE_SELECTING) return;
    dhcp_state.stats.offers_received++;
    dhcp_lease_info_t offer;
    zero_bytes(&offer, sizeof(offer));
    offer.assigned_ip = h->yiaddr;
    dhcp_parse_options(h, length, &offer);
    client->lease = offer;
    client->request_retries = 0;
    dhcp_send_request(client, &offer.dhcp_server, &offer.assigned_ip);
}

static void on_ack(dhcp_client_t* client, const dhcp_header_t* h, uint32_t length) {
    if (client->state != DHCP_STATE_REQUESTING && client->state != DHCP_STATE_RENEWING &&
        client->state != DHCP_STATE_REBINDING) {
        return;
    }
    dhcp_state.stats.acks_received++;
    if (client->state != DHCP_STATE_REQUESTING) dhcp_state.stats.lease_renewals++;
    else dhcp_state.stats.leases_acquired++;
    client->lease.assigned_ip = h->yiaddr;
    dhcp_parse_options(h, length, &client->lease);
    client->lease.lease_start_time = now_seconds();
    client->lease_acquired_time = client->lease.lease_start_time;
    client->lease.is_valid = true;
    client->state = DHCP_STATE_BOUND;
    dhcp_client_apply_lease(client);
}

static void restart(dhcp_client_t* client) {
    ip_address_t zero = {0};
    client->lease.is_valid = false;
    network_interface_set_ip_config(client->interface->interface_id, zero, zero, zero);
    dhcp_client_start_discovery(client);
}

void dhcp_client_process_packet(dhcp_client_t* client, const void* packet, uint32_t length,
                               const ip_address_t* sender_ip) {
    (void)sender_ip;
    const dhcp_header_t* h = (const dhcp_header_t*)packet;
    if (!client || !packet || length < DHCP_FIXED_SIZE) return;
    if (h->op != DHCP_BOOTREPLY || __builtin_bswap32(h->magic_cookie) != DHCP_MAGIC_COOKIE) return;
    if (__builtin_bswap32(h->xid) != client->transaction_id) return;
    for (int i = 0; i < DHCP_HLEN_ETHERNET; i++) {
        if (h->chaddr[i] != client->interface->mac_addr.addr[i]) return;
    }
    uint8_t* type = dhcp_find_option(h, length, DHCP_OPTION_MESSAGE_TYPE);
    if (!type || type[1] != 1) return;
    switch (type[2]) {
        case DHCP_OFFER: on_offer(client, h, length); break;
        case DHCP_ACK: on_ack(client, h, length); break;
        case DHCP_NAK:
            dhcp_state.stats.naks_received++;
            restart(client);
            break;
    }
}

static void receive_callback(uint16_t port, const ip_address_t* remote_ip, const void* data, uint32_t length) {
    if (port != DHCP_CLIENT_PORT || length < DHCP_FIXED_SIZE) return;
    uint32_t xid = __builtin_bswap32(((const dhcp_header_t*)data)->xid);
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        dhcp_client_t* client = dhcp_state.clients[i];
        if (client && client->transaction_id == xid) {
            dhcp_client_process_packet(client, data, length, remote_ip);
            return;
        }
    }
}

/* state machine */

bool dhcp_client_start_discovery(dhcp_client_t* client) {
    if (!client) return false;
    client->transaction_id = dhcp_generate_transaction_id();
    client->discover_retries = 0;
    client->discover_start_time = now_ms();
    return dhcp_send_discover(client);
}

bool dhcp_client_request_renewal(dhcp_client_t* client) {
    if (!client || !client->lease.is_valid) return false;
    client->transaction_id = dhcp_generate_transaction_id();
    client->state = DHCP_STATE_RENEWING;
    client->request_retries = 0;
    return dhcp_send_request(client, &client->lease.dhcp_server, &client->lease.assigned_ip);
}

bool dhcp_client_release_lease(dhcp_client_t* client) {
    if (!client) return false;
    bool sent = dhcp_send_release(client);
    ip_address_t zero = {0};
    client->lease.is_valid = false;
    client->state = DHCP_STATE_INIT;
    network_interface_set_ip_config(client->interface->interface_id, zero, zero, zero);
    return sent;
}

bool dhcp_client_check_lease_expiry(dhcp_client_t* client) {
    if (!client || !client->lease.is_valid) return false;
    uint32_t age = now_seconds() - client->lease.lease_start_time;
    if (age >= client->lease.lease_time) {
        dhcp_state.stats.lease_timeouts++;
        restart(client);
        return true;
    }
    if (age >= client->lease.rebinding_time && client->state != DHCP_STATE_REBINDING) {
        client->state = DHCP_STATE_REBINDING;
        client->request_retries = 0;
        dhcp_send_request(client, &client->lease.dhcp_server, &client->lease.assigned_ip);
    } else if (age >= client->lease.renewal_time && client->state == DHCP_STATE_BOUND && client->auto_renew) {
        dhcp_client_request_renewal(client);
    }
    return false;
}

// Called when the current wait runs out, retransmits or falls back a step
void dhcp_client_handle_timeout(dhcp_client_t* client) {
    switch (client->state) {
        case DHCP_STATE_SELECTING:
            if (++client->discover_retries < DHCP_MAX_TRIES) {
                dhcp_send_discover(client);
            } else {
                client->state = DHCP_STATE_INIT;
                set_timeout(client, DHCP_RESTART_MS);
            }
            break;
        case DHCP_STATE_REQUESTING:
            if (++client->request_retries < DHCP_MAX_TRIES) dhcp_send_request(client, &client->lease.dhcp_server, &client->lease.assigned_ip);
            else dhcp_client_start_discovery(client);
            break;
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
            if (++client->request_retries < DHCP_MAX_TRIES) dhcp_send_request(client, &client->lease.dhcp_server, &client->lease.assigned_ip);
            break;
        case DHCP_STATE_INIT:
            dhcp_client_start_discovery(client);
            break;
        default:
            break;
    }
}

void dhcp_client_state_machine(dhcp_client_t* client) {
    if (!client) return;
    if (client->state == DHCP_STATE_BOUND || client->state == DHCP_STATE_RENEWING || client->state == DHCP_STATE_REBINDING) {
        if (dhcp_client_check_lease_expiry(client)) return;
    }
    if (client->state != DHCP_STATE_BOUND && client->next_timeout && (int32_t)(now_ms() - client->next_timeout) >= 0) {
        client->next_timeout = 0;
        dhcp_client_handle_timeout(client);
    }
}

void dhcp_client_periodic_tasks(dhcp_client_t* client) {
    dhcp_client_state_machine(client);
}

void dhcp_global_periodic_tasks(void) {
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        if (dhcp_state.clients[i]) dhcp_client_state_machine(dhcp_state.clients[i]);
    }
}

bool dhcp_start_on_interface(network_interface_t* interface) {
    if (!interface) return false;
    if (interface->state != NET_INTERFACE_UP && !network_interface_bring_up(interface->interface_id)) return false;
    dhcp_client_t* client = dhcp_find_client(interface);
    if (!client) {
        uint32_t slot = NET_MAX_INTERFACES;
        for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
            if (!dhcp_state.clients[i]) { slot = i; break; }
        }
        if (slot == NET_MAX_INTERFACES || !(client = dhcp_client_create(interface))) return false;
        dhcp_state.clients[slot] = client;
        char hostname[64];
        string_copy(hostname, "apollo-");
        string_concat_n(hostname, interface->name, sizeof(hostname));
        dhcp_client_set_hostname(client, hostname);
    }
    ip_address_t zero = {0};
    network_interface_set_ip_config(interface->interface_id, zero, zero, zero);
    client->lease.is_valid = false;
    return dhcp_client_start_discovery(client);
}

void dhcp_stop_on_interface(network_interface_t* interface) {
    dhcp_client_t* client = dhcp_find_client(interface);
    if (!client) return;
    dhcp_client_release_lease(client);
    dhcp_client_destroy(client);
}

dhcp_client_t* dhcp_find_client(network_interface_t* interface) {
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        if (dhcp_state.clients[i] && dhcp_state.clients[i]->interface == interface) return dhcp_state.clients[i];
    }
    return NULL;
}

bool dhcp_auto_configure_interface(network_interface_t* interface) {
    return dhcp_start_on_interface(interface);
}

bool dhcp_configure_interface_from_lease(network_interface_t* interface, const dhcp_lease_info_t* lease) {
    if (!interface || !lease || !lease->is_valid) return false;
    return network_interface_set_ip_config(interface->interface_id, lease->assigned_ip, lease->subnet_mask, lease->gateway);
}

bool dhcp_client_set_hostname(dhcp_client_t* client, const char* hostname) {
    if (!client || !hostname || string_length(hostname) >= sizeof(client->hostname)) return false;
    string_copy(client->hostname, hostname);
    return true;
}

bool dhcp_client_set_client_identifier(dhcp_client_t* client, const char* identifier) {
    if (!client || !identifier || string_length(identifier) >= sizeof(client->client_identifier)) return false;
    string_copy(client->client_identifier, identifier);
    return true;
}

bool dhcp_client_add_requested_option(dhcp_client_t* client, uint8_t option) {
    if (!client || client->num_requested_options >= sizeof(client->requested_options)) return false;
    for (uint8_t i = 0; i < client->num_requested_options; i++) {
        if (client->requested_options[i] == option) return true;
    }
    client->requested_options[client->num_requested_options++] = option;
    return true;
}

bool dhcp_client_is_lease_valid(dhcp_client_t* client) {
    return client && client->lease.is_valid;
}

dhcp_client_state_t dhcp_client_get_state(dhcp_client_t* client) {
    return client ? client->state : DHCP_STATE_INIT;
}

const dhcp_lease_info_t* dhcp_client_get_lease_info(dhcp_client_t* client) {
    return client ? &client->lease : NULL;
}

dhcp_statistics_t* dhcp_get_statistics(void) {
    return &dhcp_state.stats;
}

void dhcp_reset_statistics(void) {
    zero_bytes(&dhcp_state.stats, sizeof(dhcp_statistics_t));
}
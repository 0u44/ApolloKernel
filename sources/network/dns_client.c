#include "dns_client.h"
#include "network_interface.h"
#include "ip_stack.h"
#include "heap_allocator.h"
#include "time_keeper.h"
#include "string_utils.h"
#include "types.h"

#define DNS_MAX_QUERIES 16
#define DNS_MAX_SERVERS 4
#define DNS_MAX_POINTER_JUMPS 16
#define DNS_RCODE_MASK 0x0F
#define DNS_POINTER_FLAG 0xC0
#define DNS_POINTER_OFFSET_MASK 0x3FFF
#define DNS_SRV_FIXED 6
#define DNS_RETRY_MS 2000

typedef struct {
    bool done;
    bool success;
    ip_address_t address;
    char name[DNS_MAX_NAME_LENGTH + 1];
    uint16_t port;
} dns_result_t;

static struct {
    dns_config_t config;
    dns_cache_entry_t cache[DNS_CACHE_SIZE];
    dns_query_t queries[DNS_MAX_QUERIES];
    dns_result_t results[DNS_MAX_QUERIES];
    dns_statistics_t stats;
    udp_socket_t* socket;
    uint32_t seed;
    bool is_initialized;
} dns_state;

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

static uint16_t be16_at(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t be32_at(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void receive_callback(uint16_t port, const ip_address_t* remote_ip, const void* data, uint32_t length) {
    (void)port;
    dns_process_response(data, length, remote_ip);
}

bool dns_client_initialize(void) {
    if (dns_state.is_initialized) return true;
    zero_bytes(&dns_state, sizeof(dns_state));
    dns_state.config.default_ttl = DNS_CACHE_TTL_DEFAULT;
    dns_state.config.query_timeout = DNS_QUERY_TIMEOUT;
    dns_state.config.max_retries = 3;
    dns_state.config.cache_enabled = true;
    dns_state.seed = (uint32_t)time_keeper_get_unix_time();
    dns_state.socket = udp_create_socket();
    if (!dns_state.socket || !udp_bind_socket(dns_state.socket, 0)) return false;
    udp_set_receive_callback(dns_state.socket, receive_callback);
    dns_state.is_initialized = true;
    return true;
}

void dns_client_shutdown(void) {
    if (!dns_state.is_initialized) return;
    udp_close_socket(dns_state.socket);
    dns_state.socket = NULL;
    dns_state.is_initialized = false;
}

bool dns_set_server(uint8_t index, const ip_address_t* server_ip) {
    if (!server_ip || index >= DNS_MAX_SERVERS) return false;
    dns_state.config.dns_servers[index] = *server_ip;
    if (index >= dns_state.config.num_dns_servers) dns_state.config.num_dns_servers = index + 1;
    return true;
}

bool dns_add_server(const ip_address_t* server_ip) {
    if (!server_ip || dns_state.config.num_dns_servers >= DNS_MAX_SERVERS) return false;
    for (uint8_t i = 0; i < dns_state.config.num_dns_servers; i++) {
        if (dns_state.config.dns_servers[i].addr == server_ip->addr) return true;
    }
    dns_state.config.dns_servers[dns_state.config.num_dns_servers++] = *server_ip;
    return true;
}

void dns_clear_servers(void) {
    dns_state.config.num_dns_servers = 0;
    zero_bytes(dns_state.config.dns_servers, sizeof(dns_state.config.dns_servers));
}

bool dns_set_config(const dns_config_t* config) {
    if (!config || config->num_dns_servers > DNS_MAX_SERVERS || config->query_timeout == 0) return false;
    dns_state.config = *config;
    return true;
}

dns_config_t* dns_get_config(void) {
    return &dns_state.config;
}

uint16_t dns_generate_transaction_id(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    dns_state.seed = dns_state.seed * 1103515245u + 12345u + lo;
    return (uint16_t)(dns_state.seed >> 8);
}

/* wire format */

uint32_t dns_encode_name(const char* hostname, uint8_t* buffer) {
    uint32_t length = string_length(hostname);
    if (!buffer || length == 0 || length > DNS_MAX_NAME_LENGTH) return 0;
    uint32_t pos = 0;
    uint32_t start = 0;
    for (uint32_t i = 0; i <= length; i++) {
        if (hostname[i] != '.' && hostname[i] != '\0') continue;
        uint32_t label = i - start;
        if (label == 0 && hostname[i] == '\0' && i > 0) break;
        if (label == 0 || label > DNS_MAX_LABEL_LENGTH) return 0;
        buffer[pos++] = (uint8_t)label;
        copy_bytes(&buffer[pos], &hostname[start], label);
        pos += label;
        start = i + 1;
    }
    buffer[pos++] = 0;
    return pos;
}

// Follows compression pointers and returns the offset just past the name at its original position
uint32_t dns_decode_name(const uint8_t* packet, uint32_t packet_length, uint32_t offset, char* hostname) {
    if (!packet || !hostname || offset >= packet_length) return 0;
    uint32_t resume = 0;
    uint32_t pos = 0;
    for (uint32_t jumps = 0; offset < packet_length;) {
        uint8_t length = packet[offset];
        if (length == 0) {
            hostname[pos] = '\0';
            return resume ? resume : offset + 1;
        }
        if ((length & DNS_POINTER_FLAG) == DNS_POINTER_FLAG) {
            if (offset + 1 >= packet_length || ++jumps > DNS_MAX_POINTER_JUMPS) return 0;
            if (!resume) resume = offset + 2;
            offset = be16_at(&packet[offset]) & DNS_POINTER_OFFSET_MASK;
            continue;
        }
        if (length > DNS_MAX_LABEL_LENGTH || offset + 1 + length > packet_length) return 0;
        if (pos + length + 1 > DNS_MAX_NAME_LENGTH) return 0;
        if (pos) hostname[pos++] = '.';
        copy_bytes(&hostname[pos], &packet[offset + 1], length);
        pos += length;
        offset += 1u + length;
    }
    return 0;
}

uint32_t dns_build_query(const char* hostname, uint16_t query_type, uint16_t transaction_id, uint8_t* buffer) {
    if (!hostname || !buffer) return 0;
    dns_header_t* h = (dns_header_t*)buffer;
    h->id = __builtin_bswap16(transaction_id);
    h->flags = __builtin_bswap16(DNS_FLAG_RD);
    h->questions = __builtin_bswap16(1);
    h->answers = 0;
    h->authority = 0;
    h->additional = 0;
    uint32_t name = dns_encode_name(hostname, buffer + sizeof(dns_header_t));
    if (name == 0) return 0;
    uint8_t* q = buffer + sizeof(dns_header_t) + name;
    q[0] = (uint8_t)(query_type >> 8);
    q[1] = (uint8_t)query_type;
    q[2] = 0;
    q[3] = DNS_CLASS_IN;
    return sizeof(dns_header_t) + name + 4;
}

bool dns_send_query(const char* hostname, uint16_t query_type, uint16_t transaction_id, const ip_address_t* dns_server) {
    if (!hostname || !dns_server || !dns_state.is_initialized) return false;
    uint8_t buffer[DNS_PACKET_MAX_SIZE];
    uint32_t length = dns_build_query(hostname, query_type, transaction_id, buffer);
    if (length == 0 || !udp_send_to(dns_state.socket, dns_server, DNS_PORT, buffer, length)) return false;
    dns_state.stats.queries_sent++;
    return true;
}

static dns_result_t* result_for(const dns_query_t* query) {
    return &dns_state.results[query - dns_state.queries];
}

static bool take_answer(dns_query_t* query, const uint8_t* packet, uint32_t length, uint32_t offset,
                        uint16_t type, uint16_t rdlength, uint32_t ttl) {
    dns_result_t* result = result_for(query);
    if (type != query->query_type) return false;
    if (type == DNS_TYPE_A && rdlength == 4) {
        copy_bytes(&result->address.addr, &packet[offset], 4);
        dns_cache_add_entry(query->hostname, &result->address, ttl ? ttl : dns_state.config.default_ttl);
        return true;
    }
    if (type == DNS_TYPE_PTR) return dns_decode_name(packet, length, offset, result->name) != 0;
    if (type == DNS_TYPE_SRV && rdlength > DNS_SRV_FIXED) {
        result->port = be16_at(&packet[offset + 4]);
        return dns_decode_name(packet, length, offset + DNS_SRV_FIXED, result->name) != 0;
    }
    return false;
}

// Walks the answer section, CNAME records are skipped because the server already follows them
bool dns_parse_response(const dns_header_t* header, uint32_t packet_length, dns_query_t* query) {
    if (!header || !query || packet_length < sizeof(dns_header_t)) return false;
    uint16_t flags = __builtin_bswap16(header->flags);
    if (!(flags & DNS_FLAG_QR) || (flags & DNS_RCODE_MASK) != DNS_RCODE_NOERROR) return false;
    const uint8_t* packet = (const uint8_t*)header;
    char name[DNS_MAX_NAME_LENGTH + 1];
    uint32_t offset = sizeof(dns_header_t);
    for (uint16_t i = 0; i < __builtin_bswap16(header->questions); i++) {
        offset = dns_decode_name(packet, packet_length, offset, name);
        if (offset == 0 || offset + 4 > packet_length) return false;
        offset += 4;
    }
    for (uint16_t i = 0; i < __builtin_bswap16(header->answers); i++) {
        offset = dns_decode_name(packet, packet_length, offset, name);
        if (offset == 0 || offset + 10 > packet_length) return false;
        uint16_t type = be16_at(&packet[offset]);
        uint32_t ttl = be32_at(&packet[offset + 4]);
        uint16_t rdlength = be16_at(&packet[offset + 8]);
        offset += 10;
        if (offset + rdlength > packet_length) return false;
        if (take_answer(query, packet, packet_length, offset, type, rdlength, ttl)) return true;
        offset += rdlength;
    }
    return false;
}

static void finish(dns_query_t* query, bool success) {
    dns_result_t* result = result_for(query);
    result->done = true;
    result->success = success;
    query->is_active = false;
    if (success) dns_state.stats.successful_resolutions++;
    else dns_state.stats.failed_resolutions++;
    if (query->callback) query->callback(query->hostname, &result->address, success, query->user_data);
}

void dns_process_response(const void* packet, uint32_t packet_length, const ip_address_t* sender_ip) {
    if (!packet || packet_length < sizeof(dns_header_t) || !sender_ip) return;
    const dns_header_t* header = (const dns_header_t*)packet;
    uint16_t id = __builtin_bswap16(header->id);
    dns_state.stats.responses_received++;
    for (uint32_t i = 0; i < DNS_MAX_QUERIES; i++) {
        dns_query_t* query = &dns_state.queries[i];
        if (query->is_active && query->transaction_id == id) {
            finish(query, dns_parse_response(header, packet_length, query));
            return;
        }
    }
}

/* cache */

bool dns_cache_lookup(const char* hostname, ip_address_t* ip_address) {
    if (!hostname || !ip_address || !dns_state.config.cache_enabled) return false;
    uint32_t now = now_seconds();
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) {
        dns_cache_entry_t* e = &dns_state.cache[i];
        if (!e->is_valid || !string_equals(e->hostname, hostname)) continue;
        if (now - e->timestamp < e->ttl) {
            *ip_address = e->ip_address;
            dns_state.stats.cache_hits++;
            return true;
        }
        e->is_valid = false;
    }
    dns_state.stats.cache_misses++;
    return false;
}

bool dns_cache_add_entry(const char* hostname, const ip_address_t* ip_address, uint32_t ttl) {
    if (!hostname || !ip_address || !dns_state.config.cache_enabled || string_length(hostname) > DNS_MAX_NAME_LENGTH) return false;
    dns_cache_entry_t* slot = NULL;
    dns_cache_entry_t* oldest = &dns_state.cache[0];
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) {
        dns_cache_entry_t* e = &dns_state.cache[i];
        if (e->is_valid && string_equals(e->hostname, hostname)) { slot = e; break; }
        if (!e->is_valid && !slot) slot = e;
        if (e->timestamp < oldest->timestamp) oldest = e;
    }
    if (!slot) slot = oldest;
    string_copy(slot->hostname, hostname);
    slot->ip_address = *ip_address;
    slot->ttl = ttl;
    slot->timestamp = now_seconds();
    slot->is_valid = true;
    return true;
}

void dns_cache_remove_entry(const char* hostname) {
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) {
        if (dns_state.cache[i].is_valid && string_equals(dns_state.cache[i].hostname, hostname)) {
            dns_state.cache[i].is_valid = false;
        }
    }
}

void dns_cache_clear(void) {
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) dns_state.cache[i].is_valid = false;
}

void dns_cache_cleanup_expired(void) {
    uint32_t now = now_seconds();
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) {
        dns_cache_entry_t* e = &dns_state.cache[i];
        if (e->is_valid && now - e->timestamp >= e->ttl) e->is_valid = false;
    }
}

uint32_t dns_cache_get_entry_count(void) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) count += dns_state.cache[i].is_valid ? 1 : 0;
    return count;
}

const dns_cache_entry_t* dns_cache_entry_at(uint32_t index) {
    return index < DNS_CACHE_SIZE && dns_state.cache[index].is_valid ? &dns_state.cache[index] : NULL;
}

/* queries */

static dns_query_t* start_query(const char* name, uint16_t type,
                                void (*callback)(const char*, const ip_address_t*, bool, void*), void* user_data) {
    if (!dns_state.is_initialized || dns_state.config.num_dns_servers == 0 || string_length(name) > DNS_MAX_NAME_LENGTH) return NULL;
    for (uint32_t i = 0; i < DNS_MAX_QUERIES; i++) {
        dns_query_t* query = &dns_state.queries[i];
        if (query->is_active) continue;
        zero_bytes(query, sizeof(*query));
        zero_bytes(&dns_state.results[i], sizeof(dns_result_t));
        query->transaction_id = dns_generate_transaction_id();
        string_copy(query->hostname, name);
        query->query_type = type;
        query->callback = callback;
        query->user_data = user_data;
        query->query_time = get_system_time();
        query->next_retry_time = query->query_time + DNS_RETRY_MS;
        query->is_active = true;
        if (!dns_send_query(name, type, query->transaction_id, &dns_state.config.dns_servers[0])) {
            query->is_active = false;
            return NULL;
        }
        return query;
    }
    return NULL;
}

static bool run_query(const char* name, uint16_t type, uint32_t timeout_ms, dns_result_t* out) {
    dns_query_t* query = start_query(name, type, NULL, NULL);
    if (!query) return false;
    dns_result_t* result = result_for(query);
    uint32_t deadline = get_system_time() + timeout_ms;
    while (!result->done && get_system_time() < deadline) network_poll();
    if (!result->done) {
        query->is_active = false;
        dns_state.stats.timeouts++;
        return false;
    }
    *out = *result;
    return result->success;
}

bool dns_resolve_hostname(const char* hostname, ip_address_t* ip_address) {
    return dns_resolve_hostname_with_timeout(hostname, ip_address, dns_state.config.query_timeout);
}

bool dns_resolve_hostname_with_timeout(const char* hostname, ip_address_t* ip_address, uint32_t timeout_ms) {
    if (!hostname || !ip_address) return false;
    if (string_to_ip_address(hostname, ip_address) || dns_cache_lookup(hostname, ip_address)) return true;
    dns_result_t result;
    if (!run_query(hostname, DNS_TYPE_A, timeout_ms, &result)) return false;
    *ip_address = result.address;
    return true;
}

dns_query_t* dns_resolve_hostname_async(const char* hostname,
    void (*callback)(const char* hostname, const ip_address_t* ip_address, bool success, void* user_data),
    void* user_data) {
    if (!hostname || !callback) return NULL;
    ip_address_t cached;
    if (string_to_ip_address(hostname, &cached) || dns_cache_lookup(hostname, &cached)) {
        callback(hostname, &cached, true, user_data);
        return NULL;
    }
    dns_query_t* query = start_query(hostname, DNS_TYPE_A, callback, user_data);
    if (!query) {
        ip_address_t none = {0};
        callback(hostname, &none, false, user_data);
    }
    return query;
}

bool dns_cancel_query(dns_query_t* query) {
    if (!query || !query->is_active) return false;
    query->is_active = false;
    return true;
}

void dns_ip_to_reverse_name(const ip_address_t* ip_address, char* reverse_name) {
    const uint8_t* octets = (const uint8_t*)&ip_address->addr;
    reverse_name[0] = '\0';
    for (int i = 3; i >= 0; i--) {
        char part[5];
        uint32_t n = 0;
        uint8_t value = octets[i];
        if (value >= 100) part[n++] = (char)('0' + value / 100);
        if (value >= 10) part[n++] = (char)('0' + (value / 10) % 10);
        part[n++] = (char)('0' + value % 10);
        part[n++] = '.';
        part[n] = '\0';
        string_concat(reverse_name, part);
    }
    string_concat(reverse_name, "in-addr.arpa");
}

bool dns_reverse_lookup(const ip_address_t* ip_address, char* hostname) {
    if (!ip_address || !hostname) return false;
    char name[DNS_MAX_NAME_LENGTH + 1];
    dns_ip_to_reverse_name(ip_address, name);
    dns_result_t result;
    if (!run_query(name, DNS_TYPE_PTR, dns_state.config.query_timeout, &result)) return false;
    string_copy(hostname, result.name);
    return true;
}

bool dns_get_host_by_name(const char* hostname, dns_host_entry_t* entry) {
    if (!entry || !dns_resolve_hostname(hostname, &entry->ip_address)) return false;
    string_copy_n(entry->hostname, hostname, sizeof(entry->hostname));
    return true;
}

bool dns_get_host_by_addr(const ip_address_t* ip_address, dns_host_entry_t* entry) {
    if (!entry || !dns_reverse_lookup(ip_address, entry->hostname)) return false;
    entry->ip_address = *ip_address;
    return true;
}

// Builds _service._protocol.domain, then resolves the target host the SRV record names
bool dns_resolve_service(const char* service, const char* protocol, const char* domain,
                        ip_address_t* ip_address, uint16_t* port) {
    if (!service || !protocol || !domain || !ip_address || !port) return false;
    char name[DNS_MAX_NAME_LENGTH + 1] = "_";
    string_concat_n(name, service, sizeof(name));
    string_concat_n(name, "._", sizeof(name));
    string_concat_n(name, protocol, sizeof(name));
    string_concat_n(name, ".", sizeof(name));
    string_concat_n(name, domain, sizeof(name));
    dns_result_t result;
    if (!run_query(name, DNS_TYPE_SRV, dns_state.config.query_timeout, &result)) return false;
    *port = result.port;
    return dns_resolve_hostname(result.name, ip_address);
}

bool dns_is_valid_hostname(const char* hostname) {
    uint32_t length = string_length(hostname);
    if (length == 0 || length > DNS_MAX_NAME_LENGTH) return false;
    for (uint32_t i = 0; i < length; i++) {
        char c = hostname[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) {
            return false;
        }
    }
    return true;
}

// Retries go to the next configured server in turn
void dns_handle_timeouts(void) {
    uint32_t now = get_system_time();
    for (uint32_t i = 0; i < DNS_MAX_QUERIES; i++) {
        dns_query_t* query = &dns_state.queries[i];
        if (!query->is_active || (int32_t)(now - query->next_retry_time) < 0) continue;
        if (query->retry_count >= dns_state.config.max_retries || dns_state.config.num_dns_servers == 0) {
            dns_state.stats.timeouts++;
            finish(query, false);
            continue;
        }
        query->retry_count++;
        query->next_retry_time = now + DNS_RETRY_MS;
        uint32_t server = query->retry_count % dns_state.config.num_dns_servers;
        dns_send_query(query->hostname, query->query_type, query->transaction_id, &dns_state.config.dns_servers[server]);
    }
}

void dns_periodic_tasks(void) {
    dns_cache_cleanup_expired();
    dns_handle_timeouts();
}

bool dns_configure_from_dhcp(const ip_address_t* dns_servers, uint8_t num_servers) {
    if (!dns_servers || num_servers == 0 || num_servers > DNS_MAX_SERVERS) return false;
    dns_clear_servers();
    for (uint8_t i = 0; i < num_servers; i++) dns_add_server(&dns_servers[i]);
    return true;
}

dns_statistics_t* dns_get_statistics(void) {
    return &dns_state.stats;
}

void dns_reset_statistics(void) {
    zero_bytes(&dns_state.stats, sizeof(dns_statistics_t));
}
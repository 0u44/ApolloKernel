#ifndef APOLLO_DNS_CLIENT_H
#define APOLLO_DNS_CLIENT_H

#include "types.h"
#include "network_interface.h"
#include "ip_stack.h"

#define DNS_PORT 53
#define DNS_MAX_NAME_LENGTH 253
#define DNS_MAX_LABEL_LENGTH 63
#define DNS_PACKET_MAX_SIZE 512
#define DNS_CACHE_SIZE 128
#define DNS_QUERY_TIMEOUT 5000  // 5 seconds in milliseconds
#define DNS_CACHE_TTL_DEFAULT 300  // 5 minutes

#define DNS_TYPE_A 1        // IPv4 address
#define DNS_TYPE_NS 2       // Name server
#define DNS_TYPE_CNAME 5    // Canonical name
#define DNS_TYPE_SOA 6      // Start of authority
#define DNS_TYPE_PTR 12     // Pointer record
#define DNS_TYPE_MX 15      // Mail exchange
#define DNS_TYPE_TXT 16     // Text record
#define DNS_TYPE_AAAA 28    // IPv6 address
#define DNS_TYPE_SRV 33     // Service location

#define DNS_CLASS_IN 1      // Internet

#define DNS_RCODE_NOERROR 0    // No error
#define DNS_RCODE_FORMERR 1    // Format error
#define DNS_RCODE_SERVFAIL 2   // Server failure
#define DNS_RCODE_NXDOMAIN 3   // Name error
#define DNS_RCODE_NOTIMP 4     // Not implemented
#define DNS_RCODE_REFUSED 5    // Refused

#define DNS_FLAG_QR 0x8000     // Query/Response
#define DNS_FLAG_AA 0x0400     // Authoritative Answer
#define DNS_FLAG_TC 0x0200     // Truncation
#define DNS_FLAG_RD 0x0100     // Recursion Desired
#define DNS_FLAG_RA 0x0080     // Recursion Available

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority;
    uint16_t additional;
} __attribute__((packed)) dns_header_t;

typedef struct {
    uint16_t type;
    uint16_t class;
} __attribute__((packed)) dns_question_t;

typedef struct {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;          // Time to live
    uint16_t rdlength;     // Resource data length
} __attribute__((packed)) dns_rr_t;

typedef struct {
    char hostname[DNS_MAX_NAME_LENGTH + 1];
    ip_address_t ip_address;
    uint32_t ttl;
    uint32_t timestamp;
    bool is_valid;
} dns_cache_entry_t;

typedef struct {
    uint16_t transaction_id;
    char hostname[DNS_MAX_NAME_LENGTH + 1];
    uint16_t query_type;
    uint32_t query_time;
    udp_socket_t* socket;
    
    void (*callback)(const char* hostname, const ip_address_t* ip_address, bool success, void* user_data);
    void* user_data;
    
    uint32_t retry_count;
    uint32_t next_retry_time;
    
    bool is_active;
} dns_query_t;

typedef struct {
    ip_address_t dns_servers[4];
    uint8_t num_dns_servers;
    uint32_t default_ttl;
    uint32_t query_timeout;
    uint32_t max_retries;
    bool cache_enabled;
} dns_config_t;


bool dns_client_initialize(void);
void dns_client_shutdown(void);

bool dns_set_server(uint8_t index, const ip_address_t* server_ip);
bool dns_add_server(const ip_address_t* server_ip);
void dns_clear_servers(void);
bool dns_set_config(const dns_config_t* config);
dns_config_t* dns_get_config(void);

bool dns_resolve_hostname(const char* hostname, ip_address_t* ip_address);
bool dns_resolve_hostname_with_timeout(const char* hostname, ip_address_t* ip_address, uint32_t timeout_ms);

dns_query_t* dns_resolve_hostname_async(const char* hostname, 
    void (*callback)(const char* hostname, const ip_address_t* ip_address, bool success, void* user_data),
    void* user_data);
bool dns_cancel_query(dns_query_t* query);

bool dns_cache_add_entry(const char* hostname, const ip_address_t* ip_address, uint32_t ttl);
bool dns_cache_lookup(const char* hostname, ip_address_t* ip_address);
void dns_cache_remove_entry(const char* hostname);
void dns_cache_clear(void);
void dns_cache_cleanup_expired(void);
uint32_t dns_cache_get_entry_count(void);
const dns_cache_entry_t* dns_cache_entry_at(uint32_t index);

void dns_process_response(const void* packet, uint32_t packet_length, const ip_address_t* sender_ip);
bool dns_send_query(const char* hostname, uint16_t query_type, uint16_t transaction_id, const ip_address_t* dns_server);

uint32_t dns_encode_name(const char* hostname, uint8_t* buffer);
uint32_t dns_decode_name(const uint8_t* packet, uint32_t packet_length, uint32_t offset, char* hostname);
bool dns_parse_response(const dns_header_t* header, uint32_t packet_length, dns_query_t* query);
uint32_t dns_build_query(const char* hostname, uint16_t query_type, uint16_t transaction_id, uint8_t* buffer);

bool dns_is_valid_hostname(const char* hostname);
uint16_t dns_generate_transaction_id(void);
void dns_periodic_tasks(void);
void dns_handle_timeouts(void);

bool dns_reverse_lookup(const ip_address_t* ip_address, char* hostname);
void dns_ip_to_reverse_name(const ip_address_t* ip_address, char* reverse_name);

typedef struct {
    uint32_t queries_sent;
    uint32_t responses_received;
    uint32_t timeouts;
    uint32_t cache_hits;
    uint32_t cache_misses;
    uint32_t successful_resolutions;
    uint32_t failed_resolutions;
} dns_statistics_t;

dns_statistics_t* dns_get_statistics(void);
void dns_reset_statistics(void);

bool dns_configure_from_dhcp(const ip_address_t* dns_servers, uint8_t num_servers);

typedef struct {
    char hostname[DNS_MAX_NAME_LENGTH + 1];
    ip_address_t ip_address;
} dns_host_entry_t;

bool dns_get_host_by_name(const char* hostname, dns_host_entry_t* entry);
bool dns_get_host_by_addr(const ip_address_t* ip_address, dns_host_entry_t* entry);

bool dns_resolve_service(const char* service, const char* protocol, const char* domain, 
                        ip_address_t* ip_address, uint16_t* port);

#endif
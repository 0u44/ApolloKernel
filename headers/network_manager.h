#ifndef APOLLO_NETWORK_MANAGER_H
#define APOLLO_NETWORK_MANAGER_H

#include "types.h"
#include "network_interface.h"
#include "ip_stack.h"
#include "dhcp_client.h"
#include "dns_client.h"

#define NETWORK_MAX_SERVICES 4
#define HTTP_DEFAULT_PORT 80

typedef enum {
    NETWORK_STATUS_DOWN = 0,
    NETWORK_STATUS_LINK_DETECTED = 1,
    NETWORK_STATUS_CONFIGURING = 2,
    NETWORK_STATUS_UP = 3,
    NETWORK_STATUS_ERROR = 4
} network_status_t;

typedef struct {
    network_status_t status;
    char interface_name[16];
    mac_address_t mac_address;
    ip_address_t ip_address;
    ip_address_t netmask;
    ip_address_t gateway;
    ip_address_t dns_server;
    bool dhcp_enabled;
    bool link_up;
    uint32_t connection_time;
} network_info_t;

typedef struct {
    uint32_t interfaces_detected;
    uint32_t interfaces_configured;
    uint32_t dhcp_leases_acquired;
    uint32_t dns_queries_sent;
    uint32_t dns_queries_successful;
    uint32_t ping_requests_sent;
    uint32_t ping_replies_received;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    uint64_t total_packets_sent;
    uint64_t total_packets_received;
} network_manager_stats_t;

typedef enum {
    PING_REPLY = 0,
    PING_TIMEOUT = 1,
    PING_UNREACHABLE = 2,
    PING_SEND_FAILED = 3
} ping_result_t;

typedef struct {
    int32_t status_code;        // HTTP status, or -1 when no response line arrived
    uint32_t body_bytes;
    uint32_t total_bytes;
    bool truncated;
    char error[96];
} http_result_t;

bool network_manager_initialize(void);
bool network_manager_initialize_hardware(void);
void network_manager_shutdown(void);
bool network_manager_is_initialized(void);
bool network_manager_has_hardware(void);
bool network_manager_is_hardware_initialized(void);

bool network_manager_scan_for_devices(void);
uint32_t network_manager_get_interface_count(void);
bool network_manager_get_interface_info(uint32_t index, network_info_t* info);
network_interface_t* network_manager_get_default_interface(void);

bool network_manager_configure_interface(const char* interface_name, const char* ip_address,
                                         const char* netmask, const char* gateway);
bool network_manager_configure_static_ip(const char* interface_name,
    const ip_address_t* ip, const ip_address_t* netmask, const ip_address_t* gateway);
bool network_manager_enable_dhcp(const char* interface_name);
bool network_manager_disable_dhcp(const char* interface_name);
bool network_manager_bring_interface_up(const char* interface_name);
bool network_manager_bring_interface_down(const char* interface_name);
bool network_manager_is_connected(void);

bool network_manager_set_dns_server(const ip_address_t* dns_server);
bool network_manager_add_dns_server(const ip_address_t* dns_server);
void network_manager_clear_dns_servers(void);
bool network_manager_resolve_hostname(const char* hostname, ip_address_t* ip_address);

ping_result_t network_manager_ping_once(const ip_address_t* target, uint16_t sequence, uint32_t timeout_ms,
                                        uint32_t* rtt_ms, ip_address_t* responder);
bool network_manager_ping(const char* hostname_or_ip, uint32_t timeout_ms);

bool network_manager_http_get(const char* hostname, uint16_t port, const char* path,
                              uint8_t* buffer, uint32_t buffer_size, http_result_t* result);
bool network_manager_download_data(const char* hostname, uint16_t port, const char* path,
                                   uint8_t* buffer, uint32_t buffer_size, uint32_t* bytes_received);
bool network_manager_send_data(const char* hostname, uint16_t port, const void* data, uint32_t data_length);

typedef uint32_t (*network_service_handler_t)(const ip_address_t* client_ip, const void* data, uint32_t length,
                                              uint8_t* reply, uint32_t reply_size);
bool network_manager_start_service(uint16_t port, network_service_handler_t handler);
bool network_manager_stop_service(uint16_t port);

void network_manager_periodic_tasks(void);
void network_manager_process_packets(void);

network_manager_stats_t* network_manager_get_statistics(void);
void network_manager_reset_statistics(void);

void network_manager_dump_interface_info(void);
void network_manager_dump_arp_table(void);
void network_manager_dump_routing_table(void);
void network_manager_dump_dns_cache(void);

#endif
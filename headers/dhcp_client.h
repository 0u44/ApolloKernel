#ifndef APOLLO_DHCP_CLIENT_H
#define APOLLO_DHCP_CLIENT_H

#include "types.h"
#include "network_interface.h"
#include "ip_stack.h"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCP_BOOTREQUEST 1
#define DHCP_BOOTREPLY 2

#define DHCP_HARDWARE_ETHERNET 1

#define DHCP_MAGIC_COOKIE 0x63825363

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8

#define DHCP_OPTION_SUBNET_MASK 1
#define DHCP_OPTION_ROUTER 3
#define DHCP_OPTION_DNS_SERVER 6
#define DHCP_OPTION_HOST_NAME 12
#define DHCP_OPTION_DOMAIN_NAME 15
#define DHCP_OPTION_BROADCAST_ADDRESS 28
#define DHCP_OPTION_REQUESTED_IP 50
#define DHCP_OPTION_LEASE_TIME 51
#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_SERVER_IDENTIFIER 54
#define DHCP_OPTION_PARAMETER_REQUEST_LIST 55
#define DHCP_OPTION_RENEWAL_TIME 58
#define DHCP_OPTION_REBINDING_TIME 59
#define DHCP_OPTION_CLIENT_IDENTIFIER 61
#define DHCP_OPTION_END 255

#define DHCP_MAX_OPTION_LENGTH 255
#define DHCP_PACKET_MIN_SIZE 300

typedef enum {
    DHCP_STATE_INIT,
    DHCP_STATE_SELECTING,
    DHCP_STATE_REQUESTING,
    DHCP_STATE_BOUND,
    DHCP_STATE_RENEWING,
    DHCP_STATE_REBINDING,
    DHCP_STATE_INIT_REBOOT,
    DHCP_STATE_REBOOTING
} dhcp_client_state_t;

typedef struct {
    uint8_t op;                    // Operation code (1 = request, 2 = reply)
    uint8_t htype;                 // Hardware address type
    uint8_t hlen;                  // Hardware address length
    uint8_t hops;
    uint32_t xid;                  // Transaction ID
    uint16_t secs;                 // Seconds since client started trying to boot
    uint16_t flags;
    ip_address_t ciaddr;           // Client IP address
    ip_address_t yiaddr;           // Your IP address
    ip_address_t siaddr;           // Server IP address
    ip_address_t giaddr;           // Gateway IP address
    uint8_t chaddr[16];            // Client hardware address
    uint8_t sname[64];             // Server name
    uint8_t file[128];             // Boot file name
    uint32_t magic_cookie;
    uint8_t options[];
} __attribute__((packed)) dhcp_header_t;

typedef struct {
    uint8_t type;
    uint8_t length;
    uint8_t data[];
} __attribute__((packed)) dhcp_option_t;

typedef struct {
    ip_address_t assigned_ip;
    ip_address_t subnet_mask;
    ip_address_t gateway;
    ip_address_t dns_server;
    ip_address_t dhcp_server;
    uint32_t lease_time;           // Lease time in seconds
    uint32_t renewal_time;         // Renewal time in seconds
    uint32_t rebinding_time;       // Rebinding time in seconds
    uint32_t lease_start_time;     // When the lease was acquired
    bool is_valid;
} dhcp_lease_info_t;

typedef struct {
    network_interface_t* interface;
    dhcp_client_state_t state;
    udp_socket_t* socket;
    
    uint32_t transaction_id;
    uint32_t discover_start_time;
    uint32_t request_start_time;
    uint32_t lease_acquired_time;
    
    dhcp_lease_info_t lease;
    
    uint32_t discover_retries;
    uint32_t request_retries;
    
    uint32_t next_timeout;
    
    bool auto_renew;
    
    char hostname[64];
    char client_identifier[32];
    uint8_t requested_options[16];
    uint8_t num_requested_options;
} dhcp_client_t;

bool dhcp_client_initialize(void);
dhcp_client_t* dhcp_client_create(network_interface_t* interface);
void dhcp_client_destroy(dhcp_client_t* client);

bool dhcp_client_start_discovery(dhcp_client_t* client);
bool dhcp_client_request_renewal(dhcp_client_t* client);
bool dhcp_client_release_lease(dhcp_client_t* client);

void dhcp_client_process_packet(dhcp_client_t* client, const void* packet, uint32_t length,
                               const ip_address_t* sender_ip);
bool dhcp_send_discover(dhcp_client_t* client);
bool dhcp_send_request(dhcp_client_t* client, const ip_address_t* server_ip, const ip_address_t* requested_ip);
bool dhcp_send_release(dhcp_client_t* client);

uint8_t* dhcp_find_option(const dhcp_header_t* header, uint32_t packet_length, uint8_t option_type);
bool dhcp_parse_options(const dhcp_header_t* header, uint32_t packet_length, dhcp_lease_info_t* lease);
uint32_t dhcp_build_options(uint8_t* options_buffer, uint8_t message_type, 
                           const dhcp_client_t* client, const ip_address_t* requested_ip,
                           const ip_address_t* server_ip);

void dhcp_client_state_machine(dhcp_client_t* client);
void dhcp_client_handle_timeout(dhcp_client_t* client);
void dhcp_client_periodic_tasks(dhcp_client_t* client);

bool dhcp_client_set_hostname(dhcp_client_t* client, const char* hostname);
bool dhcp_client_set_client_identifier(dhcp_client_t* client, const char* identifier);
bool dhcp_client_add_requested_option(dhcp_client_t* client, uint8_t option);
bool dhcp_client_is_lease_valid(dhcp_client_t* client);
dhcp_client_state_t dhcp_client_get_state(dhcp_client_t* client);
const dhcp_lease_info_t* dhcp_client_get_lease_info(dhcp_client_t* client);

uint32_t dhcp_generate_transaction_id(void);
void dhcp_client_apply_lease(dhcp_client_t* client);
bool dhcp_client_check_lease_expiry(dhcp_client_t* client);

bool dhcp_configure_interface_from_lease(network_interface_t* interface, const dhcp_lease_info_t* lease);
bool dhcp_auto_configure_interface(network_interface_t* interface);

typedef struct {
    uint32_t discovers_sent;
    uint32_t offers_received;
    uint32_t requests_sent;
    uint32_t acks_received;
    uint32_t naks_received;
    uint32_t releases_sent;
    uint32_t leases_acquired;
    uint32_t lease_renewals;
    uint32_t lease_timeouts;
} dhcp_statistics_t;

dhcp_statistics_t* dhcp_get_statistics(void);
void dhcp_reset_statistics(void);

void dhcp_global_periodic_tasks(void);
bool dhcp_start_on_interface(network_interface_t* interface);
void dhcp_stop_on_interface(network_interface_t* interface);
dhcp_client_t* dhcp_find_client(network_interface_t* interface);

#endif
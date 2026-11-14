#ifndef APOLLO_NETWORK_INTERFACE_H
#define APOLLO_NETWORK_INTERFACE_H

#include "types.h"

#define NET_MAX_INTERFACES 4
#define NET_MAC_ADDR_LEN 6
#define NET_MAX_PACKET_SIZE 1518
#define NET_MTU_SIZE 1500

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD
#define NET_CAPTURE_BYTES 96

typedef struct {
    uint8_t addr[NET_MAC_ADDR_LEN];
} mac_address_t;

typedef struct {
    uint32_t addr;
} ip_address_t;

typedef struct {
    mac_address_t dst_mac;
    mac_address_t src_mac;
    uint16_t ethertype;
    uint8_t payload[];
} __attribute__((packed)) ethernet_frame_t;

typedef enum {
    NET_INTERFACE_DOWN = 0,
    NET_INTERFACE_UP = 1,
    NET_INTERFACE_LINK_DOWN = 2,
    NET_INTERFACE_LINK_UP = 3
} net_interface_state_t;

typedef struct network_interface {
    uint32_t interface_id;
    char name[16];
    mac_address_t mac_addr;
    ip_address_t ip_addr;
    ip_address_t netmask;
    ip_address_t gateway;
    net_interface_state_t state;
    
    bool (*send_packet)(struct network_interface* iface, const void* packet, uint32_t length);
    bool (*receive_packet)(struct network_interface* iface, void* buffer, uint32_t* length);
    bool (*set_promiscuous)(struct network_interface* iface, bool enable);
    bool (*get_link_status)(struct network_interface* iface);
    
    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_errors;
    uint64_t rx_errors;
    
    void* driver_data;
    bool is_active;
} network_interface_t;

typedef struct {
    uint8_t data[NET_MAX_PACKET_SIZE];
    uint32_t length;
    network_interface_t* interface;
    uint64_t timestamp;
} network_packet_t;

typedef struct {
    uint32_t time_ms;
    bool outbound;
    uint16_t length;
    uint8_t data[NET_CAPTURE_BYTES];
} net_capture_entry_t;

void network_interface_manager_initialize(void);

// Processes received frames and protocol timers, used by every blocking network call
void network_poll(void);
uint32_t network_interface_count(void);
void network_capture_enable(bool enable);
bool network_capture_next(net_capture_entry_t* entry);
uint32_t network_capture_dropped(void);

network_interface_t* network_interface_register(const char* name, 
    bool (*send_fn)(network_interface_t*, const void*, uint32_t),
    bool (*receive_fn)(network_interface_t*, void*, uint32_t*),
    void* driver_data);

bool network_interface_unregister(uint32_t interface_id);

network_interface_t* network_interface_get_by_id(uint32_t interface_id);
network_interface_t* network_interface_get_by_name(const char* name);
network_interface_t* network_interface_get_default(void);

bool network_interface_set_mac_address(uint32_t interface_id, const mac_address_t* mac);
bool network_interface_set_ip_config(uint32_t interface_id, ip_address_t ip, ip_address_t netmask, ip_address_t gateway);
bool network_interface_bring_up(uint32_t interface_id);
bool network_interface_bring_down(uint32_t interface_id);

bool network_interface_send_ethernet_frame(network_interface_t* iface, 
    const mac_address_t* dst_mac, uint16_t ethertype, const void* payload, uint32_t payload_length);

uint32_t network_interface_list_all(network_interface_t** interfaces, uint32_t max_count);

void network_interface_process_incoming_packets(void);

bool mac_address_equals(const mac_address_t* mac1, const mac_address_t* mac2);
bool mac_address_is_broadcast(const mac_address_t* mac);
bool mac_address_is_multicast(const mac_address_t* mac);
void mac_address_copy(mac_address_t* dst, const mac_address_t* src);
void mac_address_to_string(const mac_address_t* mac, char* buffer);
bool string_to_mac_address(const char* str, mac_address_t* mac);

bool ip_address_equals(const ip_address_t* ip1, const ip_address_t* ip2);
bool ip_address_is_broadcast(const ip_address_t* ip, const ip_address_t* netmask);
bool ip_address_is_in_subnet(const ip_address_t* ip, const ip_address_t* network, const ip_address_t* netmask);
void ip_address_to_string(const ip_address_t* ip, char* buffer);
bool string_to_ip_address(const char* str, ip_address_t* ip);

uint16_t network_checksum(const void* data, uint32_t length);
uint16_t network_checksum_partial(uint16_t initial, const void* data, uint32_t length);

#endif
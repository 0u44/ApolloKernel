#ifndef APOLLO_IP_STACK_H
#define APOLLO_IP_STACK_H

#include "types.h"
#include "network_interface.h"

#define IP_VERSION_4 4
#define IP_HEADER_MIN_SIZE 20
#define IP_MAX_PACKET_SIZE 65535
#define IP_DEFAULT_TTL 64

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

#define ARP_HARDWARE_ETHERNET 1
#define ARP_PROTOCOL_IPV4 0x0800
#define ARP_OPERATION_REQUEST 1
#define ARP_OPERATION_REPLY 2
#define ARP_TABLE_SIZE 128
#define ARP_ENTRY_TIMEOUT 300  // 5 minutes in seconds

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_CODE_PORT_UNREACHABLE 3

#define UDP_HEADER_SIZE 8
#define UDP_MAX_PORTS 64
#define UDP_QUEUE_DEPTH 8
#define UDP_MAX_DATAGRAM 1472

#define IP_MAX_ROUTES 16

typedef struct {
    uint8_t version_ihl;        // Version (4 bits) + IHL (4 bits)
    uint8_t type_of_service;
    uint16_t total_length;      // Total length in bytes
    uint16_t identification;
    uint16_t flags_fragment;    // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    ip_address_t source_ip;
    ip_address_t dest_ip;
} __attribute__((packed)) ip_header_t;

typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;
    mac_address_t sender_mac;
    ip_address_t sender_ip;
    mac_address_t target_mac;
    ip_address_t target_ip;
} __attribute__((packed)) arp_header_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} __attribute__((packed)) icmp_header_t;

typedef struct {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) udp_header_t;

typedef struct {
    ip_address_t ip_addr;
    mac_address_t mac_addr;
    uint32_t timestamp;
    bool is_valid;
} arp_table_entry_t;

typedef struct {
    ip_address_t source;
    uint16_t port;
    uint16_t length;
    uint8_t data[UDP_MAX_DATAGRAM];
} udp_datagram_t;

typedef struct {
    uint16_t local_port;
    uint16_t remote_port;
    ip_address_t remote_ip;
    bool is_bound;
    bool is_connected;

    udp_datagram_t* queue;      // Ring of UDP_QUEUE_DEPTH datagrams, allocated on bind
    uint32_t queue_head;
    uint32_t queue_tail;
    uint32_t dropped;

    void (*receive_callback)(uint16_t port, const ip_address_t* remote_ip,
                           const void* data, uint32_t length);
} udp_socket_t;

typedef struct {
    ip_address_t network;
    ip_address_t netmask;
    ip_address_t gateway;       // 0 for a directly connected network
    network_interface_t* iface;
    bool in_use;
} ip_route_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    ip_address_t from;
    uint16_t identifier;
    uint16_t sequence;
    uint32_t time_ms;
} icmp_event_t;

void ip_stack_initialize(void);

bool ip_send_packet(network_interface_t* iface, const ip_address_t* dest_ip,
                   uint8_t protocol, const void* payload, uint32_t payload_length);
bool ip_send_packet_ttl(const ip_address_t* dest_ip, uint8_t protocol, uint8_t ttl,
                       const void* payload, uint32_t payload_length);
void ip_process_packet(network_interface_t* iface, const void* packet, uint32_t length);
bool ip_is_packet_for_us(const ip_header_t* ip_header, network_interface_t* iface);
uint16_t ip_calculate_checksum(const ip_header_t* header);
uint32_t ip_pseudo_header_sum(const ip_address_t* source, const ip_address_t* dest, uint8_t protocol, uint16_t length);
uint16_t ip_finish_checksum(uint32_t sum, const void* data, uint32_t length);
ip_address_t ip_source_for(const ip_address_t* dest_ip);

void arp_initialize(void);
bool arp_resolve_ip(network_interface_t* iface, const ip_address_t* ip_addr, mac_address_t* mac_addr);
void arp_add_entry(const ip_address_t* ip_addr, const mac_address_t* mac_addr);
arp_table_entry_t* arp_find_entry(const ip_address_t* ip_addr);
void arp_send_request(network_interface_t* iface, const ip_address_t* target_ip);
void arp_send_reply(network_interface_t* iface, const ip_address_t* target_ip, const mac_address_t* target_mac);
void arp_process_packet(network_interface_t* iface, const void* packet, uint32_t length);
void arp_update_table(void);
void arp_clear_table(void);
void arp_dump_table(void);

void icmp_initialize(void);
void icmp_process_packet(network_interface_t* iface, const ip_header_t* ip_header,
                        const void* icmp_packet, uint32_t length);
bool icmp_send_echo_request(network_interface_t* iface, const ip_address_t* dest_ip,
                           uint16_t identifier, uint16_t sequence, const void* data, uint16_t data_length);
bool icmp_send_echo_ttl(const ip_address_t* dest_ip, uint8_t ttl, uint16_t identifier, uint16_t sequence);
bool icmp_send_echo_reply(network_interface_t* iface, const ip_address_t* dest_ip,
                         uint16_t identifier, uint16_t sequence, const void* data, uint16_t data_length);
void icmp_send_dest_unreachable(network_interface_t* iface, const ip_address_t* dest_ip,
                               uint8_t code, const ip_header_t* original_packet);
bool icmp_wait_event(uint16_t identifier, uint16_t sequence, uint32_t timeout_ms, icmp_event_t* event);

void udp_initialize(void);
udp_socket_t* udp_create_socket(void);
bool udp_bind_socket(udp_socket_t* socket, uint16_t port);
bool udp_connect_socket(udp_socket_t* socket, const ip_address_t* remote_ip, uint16_t remote_port);
bool udp_send_data(udp_socket_t* socket, const void* data, uint32_t length);
bool udp_send_to(udp_socket_t* socket, const ip_address_t* dest_ip, uint16_t dest_port,
                 const void* data, uint32_t length);
int32_t udp_receive_data(udp_socket_t* socket, void* buffer, uint32_t buffer_size,
                        ip_address_t* sender_ip, uint16_t* sender_port);
void udp_close_socket(udp_socket_t* socket);
uint32_t udp_list_bound_ports(uint16_t* ports, uint32_t max_ports);
void udp_process_packet(network_interface_t* iface, const ip_header_t* ip_header,
                       const void* udp_packet, uint32_t length);
void udp_set_receive_callback(udp_socket_t* socket,
    void (*callback)(uint16_t port, const ip_address_t* remote_ip, const void* data, uint32_t length));

bool ip_find_route(const ip_address_t* dest_ip, network_interface_t** out_interface, ip_address_t* next_hop);
bool ip_send_via_gateway(network_interface_t* iface, const ip_address_t* dest_ip,
                        const ip_address_t* gateway, uint8_t protocol,
                        const void* payload, uint32_t payload_length);
bool ip_route_add(const ip_address_t* network, const ip_address_t* netmask, const ip_address_t* gateway,
                  network_interface_t* iface);
bool ip_route_delete(const ip_address_t* network, const ip_address_t* netmask);
uint32_t ip_route_list(ip_route_t* routes, uint32_t max_routes);

void network_process_incoming_packets(void);
void network_periodic_tasks(void);

typedef struct {
    uint64_t ip_packets_sent;
    uint64_t ip_packets_received;
    uint64_t ip_packets_dropped;
    uint64_t ip_fragments_dropped;
    uint64_t arp_requests_sent;
    uint64_t arp_replies_sent;
    uint64_t arp_requests_received;
    uint64_t arp_replies_received;
    uint64_t icmp_packets_sent;
    uint64_t icmp_packets_received;
    uint64_t udp_packets_sent;
    uint64_t udp_packets_received;
    uint64_t udp_no_port;
} network_statistics_t;

network_statistics_t* network_get_statistics(void);
void network_reset_statistics(void);

#endif
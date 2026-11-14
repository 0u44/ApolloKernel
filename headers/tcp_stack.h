#ifndef APOLLO_TCP_STACK_H
#define APOLLO_TCP_STACK_H

#include "types.h"
#include "network_interface.h"
#include "ip_stack.h"

#define TCP_HEADER_MIN_SIZE 20
#define TCP_MAX_CONNECTIONS 32
#define TCP_MSS 1460
#define TCP_RX_BUFFER_SIZE 8192
#define TCP_TX_BUFFER_SIZE 8192
#define TCP_MAX_BACKLOG 8
#define TCP_INITIAL_RTO 1000
#define TCP_MAX_RTO 16000
#define TCP_MAX_RETRANSMITS 6
#define TCP_CONNECT_TIMEOUT 10000
#define TCP_TIME_WAIT_TIMEOUT 30000    // Shortened from the RFC 793 four minutes so slots free up

typedef enum {
    TCP_CLOSED = 0,
    TCP_LISTEN = 1,
    TCP_SYN_SENT = 2,
    TCP_SYN_RECEIVED = 3,
    TCP_ESTABLISHED = 4,
    TCP_FIN_WAIT_1 = 5,
    TCP_FIN_WAIT_2 = 6,
    TCP_CLOSE_WAIT = 7,
    TCP_CLOSING = 8,
    TCP_LAST_ACK = 9,
    TCP_TIME_WAIT = 10
} tcp_state_t;

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80

typedef struct {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t header_length_reserved;  // Header length (4 bits) + reserved (4 bits)
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed)) tcp_header_t;

struct tcp_socket;
typedef struct tcp_socket tcp_socket_t;

typedef struct {
    tcp_state_t state;
    ip_address_t local_ip;
    uint16_t local_port;
    ip_address_t remote_ip;
    uint16_t remote_port;
    uint32_t bytes_queued;
    uint32_t bytes_readable;
} tcp_connection_info_t;

typedef struct {
    uint64_t segments_sent;
    uint64_t segments_received;
    uint64_t segments_retransmitted;
    uint64_t connections_established;
    uint64_t connections_closed;
    uint64_t resets_sent;
    uint64_t resets_received;
    uint64_t checksum_errors;
    uint32_t active_connections;
} tcp_statistics_t;

bool tcp_initialize(void);
void tcp_shutdown(void);
tcp_socket_t* tcp_create_socket(void);
bool tcp_bind(tcp_socket_t* socket, uint16_t port);
bool tcp_listen(tcp_socket_t* socket, uint8_t backlog);
tcp_socket_t* tcp_accept(tcp_socket_t* listening_socket);
bool tcp_connect(tcp_socket_t* socket, const ip_address_t* remote_ip, uint16_t remote_port);
int32_t tcp_send(tcp_socket_t* socket, const void* data, uint32_t length);
int32_t tcp_receive(tcp_socket_t* socket, void* buffer, uint32_t buffer_size);
void tcp_close(tcp_socket_t* socket);
tcp_state_t tcp_get_state(const tcp_socket_t* socket);
bool tcp_get_remote(const tcp_socket_t* socket, ip_address_t* ip, uint16_t* port);
uint32_t tcp_unsent_bytes(const tcp_socket_t* socket);
const char* tcp_state_name(tcp_state_t state);
uint32_t tcp_list_connections(tcp_connection_info_t* info, uint32_t max_entries);
void tcp_process_packet(network_interface_t* iface, const ip_header_t* ip_header,
                       const void* tcp_packet, uint32_t length);
void tcp_set_connect_callback(tcp_socket_t* socket, void (*callback)(tcp_socket_t*, bool));
void tcp_set_data_callback(tcp_socket_t* socket, void (*callback)(tcp_socket_t*, const void*, uint32_t));
void tcp_set_close_callback(tcp_socket_t* socket, void (*callback)(tcp_socket_t*));
void tcp_process_timers(void);
tcp_statistics_t* tcp_get_statistics(void);
void tcp_reset_statistics(void);

#endif
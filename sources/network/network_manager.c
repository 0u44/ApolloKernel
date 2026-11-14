#include "network_manager.h"
#include "network_interface.h"
#include "ip_stack.h"
#include "tcp_stack.h"
#include "dhcp_client.h"
#include "dns_client.h"
#include "rtl8139_driver.h"
#include "intel_e1000.h"
#include "pci_scan.h"
#include "heap_allocator.h"
#include "terminal.h"
#include "time_keeper.h"
#include "string_utils.h"
#include "types.h"

#define PING_DATA_SIZE 32
#define PING_IDENTIFIER_BASE 0x4150
#define HTTP_REQUEST_SIZE 512
#define HTTP_IDLE_TIMEOUT_MS 10000
#define SERVICE_BUFFER 1024
#define SERVICE_IDLE_MS 30000
#define SEND_TIMEOUT_MS 10000
#define PCI_SCAN_MAX 8

typedef struct {
    bool in_use;
    uint16_t port;
    tcp_socket_t* listener;
    tcp_socket_t* client;
    uint32_t last_activity;
    network_service_handler_t handler;
} service_t;

static struct {
    network_manager_stats_t stats;
    service_t services[NETWORK_MAX_SERVICES];
    bool is_initialized;
    bool hardware_init_attempted;
    bool hardware_available;
    bool polling;
    uint16_t ping_identifier;
} nm;

/* polling */

// Nested calls only drain frames, so a timer that sends cannot recurse into the timers again
void network_poll(void) {
    if (nm.polling) {
        network_interface_process_incoming_packets();
        return;
    }
    nm.polling = true;
    network_interface_process_incoming_packets();
    tcp_process_timers();
    dhcp_global_periodic_tasks();
    dns_handle_timeouts();
    nm.polling = false;
}

static void service_tasks(void);

void network_manager_process_packets(void) {
    network_poll();
}

void network_manager_periodic_tasks(void) {
    if (!nm.is_initialized) return;
    network_poll();
    dns_cache_cleanup_expired();
    network_periodic_tasks();
    service_tasks();
}

/* initialization */

static void bring_up_all(void) {
    network_interface_t* interfaces[NET_MAX_INTERFACES];
    uint32_t count = network_interface_list_all(interfaces, NET_MAX_INTERFACES);
    for (uint32_t i = 0; i < count; i++) network_interface_bring_up(interfaces[i]->interface_id);
    nm.stats.interfaces_detected = count;
}

bool network_manager_initialize_hardware(void) {
    if (nm.hardware_init_attempted) return nm.hardware_available;
    nm.hardware_init_attempted = true;
    bool rtl = rtl8139_driver_initialize();
    bool e1000 = intel_e1000_driver_initialize();
    nm.hardware_available = rtl || e1000 || network_interface_count() > 0;
    bring_up_all();
    return nm.hardware_available;
}

bool network_manager_initialize(void) {
    if (nm.is_initialized) return true;
    network_interface_manager_initialize();
    ip_stack_initialize();
    tcp_initialize();
    dhcp_client_initialize();
    dns_client_initialize();
    nm.ping_identifier = (uint16_t)(PING_IDENTIFIER_BASE + (get_system_time() & 0xFF));
    nm.is_initialized = true;
    network_manager_initialize_hardware();
    return true;
}

void network_manager_shutdown(void) {
    if (!nm.is_initialized) return;
    for (uint32_t i = 0; i < NETWORK_MAX_SERVICES; i++) {
        if (nm.services[i].in_use) network_manager_stop_service(nm.services[i].port);
    }
    network_interface_t* interfaces[NET_MAX_INTERFACES];
    uint32_t count = network_interface_list_all(interfaces, NET_MAX_INTERFACES);
    for (uint32_t i = 0; i < count; i++) {
        dhcp_stop_on_interface(interfaces[i]);
        network_interface_bring_down(interfaces[i]->interface_id);
    }
    nm.is_initialized = false;
}

bool network_manager_is_initialized(void) {
    return nm.is_initialized;
}

bool network_manager_has_hardware(void) {
    return nm.hardware_available;
}

bool network_manager_is_hardware_initialized(void) {
    return nm.hardware_init_attempted && nm.hardware_available;
}

bool network_manager_scan_for_devices(void) {
    pci_network_device_t devices[PCI_SCAN_MAX];
    uint32_t found = 0;
    pci_find_network_devices(devices, PCI_SCAN_MAX, &found);
    nm.hardware_init_attempted = false;
    return network_manager_initialize_hardware() && found > 0;
}

/* interfaces */

uint32_t network_manager_get_interface_count(void) {
    return network_interface_count();
}

network_interface_t* network_manager_get_default_interface(void) {
    return network_interface_get_default();
}

bool network_manager_get_interface_info(uint32_t index, network_info_t* info) {
    network_interface_t* interfaces[NET_MAX_INTERFACES];
    uint32_t count = network_interface_list_all(interfaces, NET_MAX_INTERFACES);
    if (!info || index >= count) return false;
    network_interface_t* iface = interfaces[index];
    for (uint32_t i = 0; i < sizeof(*info); i++) ((uint8_t*)info)[i] = 0;
    string_copy_n(info->interface_name, iface->name, sizeof(info->interface_name));
    info->mac_address = iface->mac_addr;
    info->ip_address = iface->ip_addr;
    info->netmask = iface->netmask;
    info->gateway = iface->gateway;
    dns_config_t* dns = dns_get_config();
    if (dns->num_dns_servers) info->dns_server = dns->dns_servers[0];
    dhcp_client_t* client = dhcp_find_client(iface);
    info->dhcp_enabled = client != NULL;
    info->link_up = iface->get_link_status ? iface->get_link_status(iface) : iface->state == NET_INTERFACE_UP;
    if (iface->state != NET_INTERFACE_UP) info->status = NETWORK_STATUS_DOWN;
    else if (iface->ip_addr.addr) info->status = NETWORK_STATUS_UP;
    else if (client) info->status = NETWORK_STATUS_CONFIGURING;
    else info->status = NETWORK_STATUS_LINK_DETECTED;
    info->connection_time = client && client->lease.is_valid ? client->lease.lease_start_time : 0;
    return true;
}

bool network_manager_configure_static_ip(const char* interface_name,
    const ip_address_t* ip, const ip_address_t* netmask, const ip_address_t* gateway) {
    network_interface_t* iface = network_interface_get_by_name(interface_name);
    if (!iface || !ip) return false;
    dhcp_stop_on_interface(iface);
    ip_address_t mask = netmask ? *netmask : (ip_address_t){0};
    ip_address_t gw = gateway ? *gateway : (ip_address_t){0};
    if (!network_interface_set_ip_config(iface->interface_id, *ip, mask, gw)) return false;
    nm.stats.interfaces_configured++;
    return network_interface_bring_up(iface->interface_id);
}

bool network_manager_configure_interface(const char* interface_name, const char* ip_address,
                                         const char* netmask, const char* gateway) {
    ip_address_t ip, mask = {0}, gw = {0};
    if (!ip_address || !string_to_ip_address(ip_address, &ip)) return false;
    if (netmask && !string_to_ip_address(netmask, &mask)) return false;
    if (gateway && !string_to_ip_address(gateway, &gw)) return false;
    return network_manager_configure_static_ip(interface_name, &ip, &mask, &gw);
}

bool network_manager_enable_dhcp(const char* interface_name) {
    network_interface_t* iface = network_interface_get_by_name(interface_name);
    return iface && dhcp_start_on_interface(iface);
}

bool network_manager_disable_dhcp(const char* interface_name) {
    network_interface_t* iface = network_interface_get_by_name(interface_name);
    if (!iface || !dhcp_find_client(iface)) return false;
    dhcp_stop_on_interface(iface);
    return true;
}

bool network_manager_bring_interface_up(const char* interface_name) {
    network_interface_t* iface = network_interface_get_by_name(interface_name);
    return iface && network_interface_bring_up(iface->interface_id);
}

bool network_manager_bring_interface_down(const char* interface_name) {
    network_interface_t* iface = network_interface_get_by_name(interface_name);
    return iface && network_interface_bring_down(iface->interface_id);
}

bool network_manager_is_connected(void) {
    network_interface_t* iface = network_interface_get_default();
    return iface && iface->state == NET_INTERFACE_UP && iface->ip_addr.addr != 0;
}

/* names */

bool network_manager_set_dns_server(const ip_address_t* dns_server) {
    if (!dns_server) return false;
    dns_clear_servers();
    return dns_add_server(dns_server);
}

bool network_manager_add_dns_server(const ip_address_t* dns_server) {
    return dns_add_server(dns_server);
}

void network_manager_clear_dns_servers(void) {
    dns_clear_servers();
}

bool network_manager_resolve_hostname(const char* hostname, ip_address_t* ip_address) {
    if (!hostname || !ip_address) return false;
    if (string_to_ip_address(hostname, ip_address)) return true;
    nm.stats.dns_queries_sent++;
    if (!dns_resolve_hostname(hostname, ip_address)) return false;
    nm.stats.dns_queries_successful++;
    return true;
}

/* ping */

ping_result_t network_manager_ping_once(const ip_address_t* target, uint16_t sequence, uint32_t timeout_ms,
                                        uint32_t* rtt_ms, ip_address_t* responder) {
    uint8_t data[PING_DATA_SIZE];
    for (uint32_t i = 0; i < PING_DATA_SIZE; i++) data[i] = (uint8_t)i;
    uint32_t start = get_system_time();
    if (!icmp_send_echo_request(NULL, target, nm.ping_identifier, sequence, data, PING_DATA_SIZE)) return PING_SEND_FAILED;
    nm.stats.ping_requests_sent++;
    icmp_event_t event;
    if (!icmp_wait_event(nm.ping_identifier, sequence, timeout_ms, &event)) return PING_TIMEOUT;
    if (rtt_ms) *rtt_ms = event.time_ms - start;
    if (responder) *responder = event.from;
    if (event.type != ICMP_TYPE_ECHO_REPLY) return PING_UNREACHABLE;
    nm.stats.ping_replies_received++;
    return PING_REPLY;
}

bool network_manager_ping(const char* hostname_or_ip, uint32_t timeout_ms) {
    ip_address_t target;
    if (!network_manager_resolve_hostname(hostname_or_ip, &target)) return false;
    return network_manager_ping_once(&target, 1, timeout_ms, NULL, NULL) == PING_REPLY;
}

/* TCP clients */

static tcp_socket_t* open_connection(const char* hostname, uint16_t port, char* error, uint32_t error_size) {
    ip_address_t ip;
    if (!network_manager_resolve_hostname(hostname, &ip)) {
        string_copy_n(error, "could not resolve host name", error_size);
        return NULL;
    }
    tcp_socket_t* socket = tcp_create_socket();
    if (!socket) {
        string_copy_n(error, "no free TCP socket", error_size);
        return NULL;
    }
    if (!tcp_connect(socket, &ip, port)) {
        string_copy_n(error, "connection refused or timed out", error_size);
        tcp_close(socket);
        return NULL;
    }
    return socket;
}

static bool send_all(tcp_socket_t* socket, const uint8_t* data, uint32_t length) {
    uint32_t sent = 0;
    uint32_t deadline = get_system_time() + SEND_TIMEOUT_MS;
    while (sent < length && get_system_time() < deadline) {
        int32_t n = tcp_send(socket, data + sent, length - sent);
        if (n < 0) return false;
        sent += (uint32_t)n;
        if (sent < length) network_poll();
    }
    return sent == length;
}

static bool wait_flushed(tcp_socket_t* socket) {
    uint32_t deadline = get_system_time() + SEND_TIMEOUT_MS;
    while (tcp_unsent_bytes(socket) && get_system_time() < deadline) network_poll();
    return tcp_unsent_bytes(socket) == 0;
}

static uint32_t receive_until_closed(tcp_socket_t* socket, uint8_t* buffer, uint32_t buffer_size, bool* truncated) {
    uint32_t total = 0;
    uint8_t discard[256];
    uint32_t deadline = get_system_time() + HTTP_IDLE_TIMEOUT_MS;
    *truncated = false;
    while (get_system_time() < deadline) {
        int32_t n = total < buffer_size ? tcp_receive(socket, buffer + total, buffer_size - total)
                                        : tcp_receive(socket, discard, sizeof(discard));
        if (n < 0) break;
        if (n == 0) { network_poll(); continue; }
        if (total >= buffer_size) *truncated = true;
        else total += (uint32_t)n;
        deadline = get_system_time() + HTTP_IDLE_TIMEOUT_MS;
    }
    return total;
}

static int32_t parse_status(const uint8_t* buffer, uint32_t length) {
    if (length < 12 || buffer[0] != 'H' || buffer[1] != 'T' || buffer[2] != 'T' || buffer[3] != 'P') return -1;
    uint32_t i = 0;
    while (i < length && buffer[i] != ' ') i++;
    int32_t code = 0;
    for (i++; i < length && buffer[i] >= '0' && buffer[i] <= '9'; i++) code = code * 10 + (buffer[i] - '0');
    return code;
}

static uint32_t body_offset(const uint8_t* buffer, uint32_t length) {
    for (uint32_t i = 0; i + 3 < length; i++) {
        if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n') return i + 4;
    }
    return length;
}

// HTTP/1.0 with Connection close, so the end of the body is the end of the connection
bool network_manager_http_get(const char* hostname, uint16_t port, const char* path,
                              uint8_t* buffer, uint32_t buffer_size, http_result_t* result) {
    for (uint32_t i = 0; i < sizeof(*result); i++) ((uint8_t*)result)[i] = 0;
    result->status_code = -1;
    tcp_socket_t* socket = open_connection(hostname, port, result->error, sizeof(result->error));
    if (!socket) return false;

    char request[HTTP_REQUEST_SIZE] = "GET ";
    string_concat_n(request, path && path[0] ? path : "/", sizeof(request));
    string_concat_n(request, " HTTP/1.0\r\nHost: ", sizeof(request));
    string_concat_n(request, hostname, sizeof(request));
    string_concat_n(request, "\r\nUser-Agent: Apollo\r\nConnection: close\r\n\r\n", sizeof(request));
    if (!send_all(socket, (const uint8_t*)request, string_length(request))) {
        string_copy_n(result->error, "request could not be sent", sizeof(result->error));
        tcp_close(socket);
        return false;
    }
    result->total_bytes = receive_until_closed(socket, buffer, buffer_size, &result->truncated);
    tcp_close(socket);

    result->status_code = parse_status(buffer, result->total_bytes);
    if (result->status_code < 0) {
        string_copy_n(result->error, "no HTTP status line in the response", sizeof(result->error));
        return false;
    }
    uint32_t start = body_offset(buffer, result->total_bytes);
    result->body_bytes = result->total_bytes - start;
    for (uint32_t i = 0; i < result->body_bytes; i++) buffer[i] = buffer[start + i];
    return true;
}

bool network_manager_download_data(const char* hostname, uint16_t port, const char* path,
                                   uint8_t* buffer, uint32_t buffer_size, uint32_t* bytes_received) {
    http_result_t result;
    bool ok = network_manager_http_get(hostname, port, path, buffer, buffer_size, &result);
    if (bytes_received) *bytes_received = result.body_bytes;
    return ok && result.status_code >= 200 && result.status_code < 300;
}

bool network_manager_send_data(const char* hostname, uint16_t port, const void* data, uint32_t data_length) {
    char error[64];
    tcp_socket_t* socket = open_connection(hostname, port, error, sizeof(error));
    if (!socket) return false;
    bool ok = send_all(socket, (const uint8_t*)data, data_length) && wait_flushed(socket);
    tcp_close(socket);
    return ok;
}

/* services */

static service_t* find_service(uint16_t port) {
    for (uint32_t i = 0; i < NETWORK_MAX_SERVICES; i++) {
        if (nm.services[i].in_use && nm.services[i].port == port) return &nm.services[i];
    }
    return NULL;
}

bool network_manager_start_service(uint16_t port, network_service_handler_t handler) {
    if (!handler || port == 0 || find_service(port)) return false;
    service_t* slot = NULL;
    for (uint32_t i = 0; i < NETWORK_MAX_SERVICES && !slot; i++) {
        if (!nm.services[i].in_use) slot = &nm.services[i];
    }
    if (!slot) return false;
    tcp_socket_t* listener = tcp_create_socket();
    if (!listener || !tcp_bind(listener, port) || !tcp_listen(listener, TCP_MAX_BACKLOG)) {
        if (listener) tcp_close(listener);
        return false;
    }
    *slot = (service_t){true, port, listener, NULL, 0, handler};
    return true;
}

bool network_manager_stop_service(uint16_t port) {
    service_t* service = find_service(port);
    if (!service) return false;
    if (service->client) tcp_close(service->client);
    tcp_close(service->listener);
    service->in_use = false;
    return true;
}

// Each service handles one client at a time and replies with whatever its handler returns
static void serve(service_t* service) {
    if (!service->client) {
        service->client = tcp_accept(service->listener);
        service->last_activity = get_system_time();
        if (!service->client) return;
    }
    uint8_t request[SERVICE_BUFFER];
    uint8_t reply[SERVICE_BUFFER];
    int32_t n = tcp_receive(service->client, request, sizeof(request));
    if (n > 0) {
        ip_address_t client_ip;
        tcp_get_remote(service->client, &client_ip, NULL);
        uint32_t reply_length = service->handler(&client_ip, request, (uint32_t)n, reply, sizeof(reply));
        if (reply_length) tcp_send(service->client, reply, reply_length);
        service->last_activity = get_system_time();
    }
    if (n < 0 || get_system_time() - service->last_activity > SERVICE_IDLE_MS) {
        tcp_close(service->client);
        service->client = NULL;
    }
}

static void service_tasks(void) {
    for (uint32_t i = 0; i < NETWORK_MAX_SERVICES; i++) {
        if (nm.services[i].in_use) serve(&nm.services[i]);
    }
}

/* statistics and dumps */

network_manager_stats_t* network_manager_get_statistics(void) {
    network_interface_t* interfaces[NET_MAX_INTERFACES];
    uint32_t count = network_interface_list_all(interfaces, NET_MAX_INTERFACES);
    nm.stats.total_packets_sent = nm.stats.total_packets_received = 0;
    nm.stats.total_bytes_sent = nm.stats.total_bytes_received = 0;
    for (uint32_t i = 0; i < count; i++) {
        nm.stats.total_packets_sent += interfaces[i]->tx_packets;
        nm.stats.total_packets_received += interfaces[i]->rx_packets;
        nm.stats.total_bytes_sent += interfaces[i]->tx_bytes;
        nm.stats.total_bytes_received += interfaces[i]->rx_bytes;
    }
    nm.stats.dhcp_leases_acquired = dhcp_get_statistics()->leases_acquired;
    return &nm.stats;
}

void network_manager_reset_statistics(void) {
    for (uint32_t i = 0; i < sizeof(nm.stats); i++) ((uint8_t*)&nm.stats)[i] = 0;
    network_reset_statistics();
    dhcp_reset_statistics();
    dns_reset_statistics();
    tcp_reset_statistics();
}

static void write_address_line(const char* label, const ip_address_t* ip) {
    char text[16];
    terminal_write_string(label);
    if (ip->addr) {
        ip_address_to_string(ip, text);
        terminal_write_string(text);
    } else {
        terminal_write_string("not configured");
    }
    terminal_write_string("\n");
}

void network_manager_dump_interface_info(void) {
    network_interface_t* interfaces[NET_MAX_INTERFACES];
    uint32_t count = network_interface_list_all(interfaces, NET_MAX_INTERFACES);
    if (count == 0) {
        terminal_write_string("Error: no network interfaces registered\n");
        terminal_write_string("  Hardware scan attempted: ");
        terminal_write_string(nm.hardware_init_attempted ? "yes" : "no");
        terminal_write_string("  Network devices found: ");
        terminal_write_string(nm.hardware_available ? "yes" : "no");
        terminal_write_string("\n\nFor QEMU, start with:\n");
        terminal_write_string("  -netdev user,id=net0 -device rtl8139,netdev=net0\n");
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        network_interface_t* iface = interfaces[i];
        char mac[18];
        mac_address_to_string(&iface->mac_addr, mac);
        terminal_write_string(iface->name);
        terminal_write_string(iface->state == NET_INTERFACE_UP ? "  UP  " : "  DOWN  ");
        terminal_write_string(mac);
        terminal_write_string(dhcp_find_client(iface) ? "  dhcp\n" : "\n");
        write_address_line("  inet     ", &iface->ip_addr);
        write_address_line("  netmask  ", &iface->netmask);
        write_address_line("  gateway  ", &iface->gateway);
        terminal_write_string("  RX packets ");
        terminal_write_uint((uint32_t)iface->rx_packets);
        terminal_write_string(" bytes ");
        terminal_write_uint((uint32_t)iface->rx_bytes);
        terminal_write_string(" errors ");
        terminal_write_uint((uint32_t)iface->rx_errors);
        terminal_write_string("\n  TX packets ");
        terminal_write_uint((uint32_t)iface->tx_packets);
        terminal_write_string(" bytes ");
        terminal_write_uint((uint32_t)iface->tx_bytes);
        terminal_write_string(" errors ");
        terminal_write_uint((uint32_t)iface->tx_errors);
        terminal_write_string("\n");
    }
}

void network_manager_dump_arp_table(void) {
    arp_dump_table();
}

void network_manager_dump_routing_table(void) {
    ip_route_t routes[IP_MAX_ROUTES + 2 * NET_MAX_INTERFACES];
    uint32_t count = ip_route_list(routes, sizeof(routes) / sizeof(routes[0]));
    terminal_write_string("Destination     Netmask         Gateway         Iface  Type\n");
    for (uint32_t i = 0; i < count; i++) {
        char text[16];
        const ip_address_t* fields[3] = {&routes[i].network, &routes[i].netmask, &routes[i].gateway};
        for (int f = 0; f < 3; f++) {
            if (f == 2 && fields[f]->addr == 0) string_copy(text, "direct");
            else ip_address_to_string(fields[f], text);
            terminal_write_string(text);
            for (uint32_t pad = string_length(text); pad < 16; pad++) terminal_write_char(' ');
        }
        terminal_write_string(routes[i].iface ? routes[i].iface->name : "-");
        terminal_write_string(routes[i].in_use ? "   static\n" : "   interface\n");
    }
    if (count == 0) terminal_write_string("(no routes, no interface has an address)\n");
}

void network_manager_dump_dns_cache(void) {
    dns_config_t* config = dns_get_config();
    terminal_write_string("DNS servers:");
    for (uint8_t i = 0; i < config->num_dns_servers; i++) {
        char text[16];
        ip_address_to_string(&config->dns_servers[i], text);
        terminal_write_string(" ");
        terminal_write_string(text);
    }
    terminal_write_string(config->num_dns_servers ? "\n" : " none\n");
    uint32_t now = (uint32_t)time_keeper_get_uptime_seconds();
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) {
        const dns_cache_entry_t* e = dns_cache_entry_at(i);
        if (!e) continue;
        char text[16];
        ip_address_to_string(&e->ip_address, text);
        terminal_write_string("  ");
        terminal_write_string(e->hostname);
        terminal_write_string("  ");
        terminal_write_string(text);
        terminal_write_string("  ttl ");
        terminal_write_uint(e->ttl - (now - e->timestamp));
        terminal_write_string("s\n");
    }
}
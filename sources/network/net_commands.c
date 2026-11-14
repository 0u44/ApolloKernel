#include "net_commands.h"
#include "network_manager.h"
#include "network_interface.h"
#include "ip_stack.h"
#include "tcp_stack.h"
#include "dhcp_client.h"
#include "dns_client.h"
#include "input_manager.h"
#include "filesystem.h"
#include "terminal.h"
#include "time_keeper.h"
#include "string_utils.h"
#include "types.h"

#define PING_DEFAULT_COUNT 4
#define PING_TIMEOUT_MS 2000
#define PING_INTERVAL_MS 1000
#define DHCP_WAIT_MS 15000
#define WGET_BUFFER FS_TOOL_BUFFER_SIZE
#define WGET_PREVIEW 1000
#define TRACE_MAX_HOPS 30
#define TRACE_TIMEOUT_MS 2000
#define TRACE_IDENTIFIER 0x5452
#define TCPDUMP_DEFAULT_COUNT 10
#define TELNET_IAC 255
#define TELNET_DONT 254
#define TELNET_DO 253
#define TELNET_WONT 252
#define TELNET_WILL 251
#define TELNET_SB 250
#define TELNET_SE 240
#define ASCII_ESCAPE 27
#define IPV4_BITS 32
#define ECHO_PORT_MAX 65535
#define ETH_HEADER 14

/* small helpers */

static uint32_t parse_uint(const char* text, bool* ok) {
    uint32_t value = 0;
    *ok = text && *text;
    for (; text && *text; text++) {
        if (*text < '0' || *text > '9') { *ok = false; return 0; }
        value = value * 10 + (uint32_t)(*text - '0');
    }
    return value;
}

static void write_ip(const ip_address_t* ip) {
    char text[16];
    ip_address_to_string(ip, text);
    terminal_write_string(text);
}

static void write_padded(const char* text, uint32_t width) {
    terminal_write_string(text);
    for (uint32_t i = string_length(text); i < width; i++) terminal_write_char(' ');
}

static void write_endpoint(const ip_address_t* ip, uint16_t port, uint32_t width) {
    char text[24];
    ip_address_to_string(ip, text);
    uint32_t pos = string_length(text);
    text[pos++] = ':';
    char digits[6];
    uint32_t n = 0;
    do { digits[n++] = (char)('0' + port % 10); port /= 10; } while (port);
    while (n > 0) text[pos++] = digits[--n];
    text[pos] = '\0';
    write_padded(text, width);
}

static bool key_pressed(void) {
    if (!input_manager_has_input()) return false;
    return input_manager_scancode_to_ascii(input_manager_read_scancode()) != 0;
}

static bool resolve_or_report(const char* host, ip_address_t* ip) {
    if (network_manager_resolve_hostname(host, ip)) return true;
    terminal_set_color(12, 0);
    terminal_write_string("Error: cannot resolve '");
    terminal_write_string(host);
    terminal_write_string(dns_get_config()->num_dns_servers ? "', the DNS query failed or timed out\n"
                                                            : "', no DNS server is configured, run dhcp first\n");
    terminal_set_color(7, 0);
    return false;
}

/* failure reports */

static const char* dhcp_state_name(dhcp_client_state_t state) {
    switch (state) {
        case DHCP_STATE_INIT: return "INIT";
        case DHCP_STATE_SELECTING: return "SELECTING";
        case DHCP_STATE_REQUESTING: return "REQUESTING";
        case DHCP_STATE_BOUND: return "BOUND";
        case DHCP_STATE_RENEWING: return "RENEWING";
        case DHCP_STATE_REBINDING: return "REBINDING";
        case DHCP_STATE_INIT_REBOOT: return "INIT_REBOOT";
        case DHCP_STATE_REBOOTING: return "REBOOTING";
    }
    return "UNKNOWN";
}

void print_qemu_network_hint(void) {
    terminal_write_string("\nFor QEMU, start with:\n");
    terminal_write_string("  -netdev user,id=net0 -device rtl8139,netdev=net0\n");
}

void print_dhcp_failure(network_interface_t* iface) {
    dhcp_statistics_t* stats = dhcp_get_statistics();
    terminal_write_string("Error: DHCP timed out on ");
    terminal_write_string(iface->name);
    terminal_write_string(", no address assigned\n");
    dhcp_client_t* client = dhcp_find_client(iface);
    terminal_write_string("  Client state: ");
    terminal_write_string(client ? dhcp_state_name(client->state) : "no client registered");
    terminal_write_string("\n  DISCOVER sent: ");
    terminal_write_uint(stats->discovers_sent);
    terminal_write_string("  OFFER received: ");
    terminal_write_uint(stats->offers_received);
    terminal_write_string("\n  REQUEST sent:  ");
    terminal_write_uint(stats->requests_sent);
    terminal_write_string("  ACK received: ");
    terminal_write_uint(stats->acks_received);
    terminal_write_string("  NAK received: ");
    terminal_write_uint(stats->naks_received);
    terminal_write_string("\n  Interface RX packets: ");
    terminal_write_uint((uint32_t)iface->rx_packets);
    terminal_write_string("  TX packets: ");
    terminal_write_uint((uint32_t)iface->tx_packets);
    terminal_write_string("  TX errors: ");
    terminal_write_uint((uint32_t)iface->tx_errors);
    terminal_write_string("\n");
}

void print_arp_failure(network_interface_t* iface, const ip_address_t* target) {
    network_statistics_t* stats = network_get_statistics();
    terminal_write_string("Error: no ARP reply from ");
    write_ip(target);
    terminal_write_string(" on ");
    terminal_write_string(iface->name);
    terminal_write_string("\n  ARP requests sent: ");
    terminal_write_uint((uint32_t)stats->arp_requests_sent);
    terminal_write_string("  ARP replies received: ");
    terminal_write_uint((uint32_t)stats->arp_replies_received);
    terminal_write_string("\n  Interface RX packets: ");
    terminal_write_uint((uint32_t)iface->rx_packets);
    terminal_write_string("  TX errors: ");
    terminal_write_uint((uint32_t)iface->tx_errors);
    terminal_write_string("\n");
}

void print_network_error(const char* text, uint32_t value, const char* tail) {
    terminal_set_color(12, 0);
    terminal_write_string("  Error: ");
    terminal_write_string(text);
    if (tail) {
        terminal_write_uint(value);
        terminal_write_string(tail);
    }
    terminal_write_string("\n");
    terminal_set_color(7, 0);
}

// Prints each failing condition with its counter and returns how many were found
uint32_t print_network_errors(network_interface_t* iface) {
    if (!iface) {
        print_network_error("no network interface is registered", 0, NULL);
        return 1;
    }
    network_statistics_t* net = network_get_statistics();
    dhcp_statistics_t* dhcp = dhcp_get_statistics();
    uint32_t errors = 0;
    if (iface->state != NET_INTERFACE_UP) { print_network_error("interface is not UP, state ", iface->state, ""); errors++; }
    if (iface->ip_addr.addr == 0) { print_network_error("interface has no IP address", 0, NULL); errors++; }
    if (iface->rx_errors > 0) { print_network_error("receive errors: ", (uint32_t)iface->rx_errors, ""); errors++; }
    if (iface->tx_errors > 0) { print_network_error("transmit errors: ", (uint32_t)iface->tx_errors, ""); errors++; }
    if (net->arp_requests_sent > 0 && net->arp_replies_received == 0) {
        print_network_error("ARP replies received: 0, requests sent: ", (uint32_t)net->arp_requests_sent, "");
        errors++;
    }
    if (dhcp->discovers_sent > 0 && dhcp->offers_received == 0) {
        print_network_error("DHCP OFFER received: 0, DISCOVER sent: ", dhcp->discovers_sent, "");
        errors++;
    }
    if (iface->tx_packets > 0 && iface->rx_packets == 0) {
        print_network_error("packets received: 0, packets sent: ", (uint32_t)iface->tx_packets, "");
        errors++;
    }
    return errors;
}

void print_network_result(network_interface_t* iface) {
    if (print_network_errors(iface) == 0) {
        terminal_set_color(10, 0);
        terminal_write_string("  No errors\n");
        terminal_set_color(7, 0);
        return;
    }
    print_qemu_network_hint();
}

/* ping */

typedef struct {
    uint32_t sent;
    uint32_t received;
    uint32_t min;
    uint32_t max;
    uint32_t total;
} ping_stats_t;

static void ping_report(ping_result_t result, uint16_t seq, uint32_t rtt, const ip_address_t* from, ping_stats_t* s) {
    if (result == PING_REPLY) {
        terminal_write_string("Reply from ");
        write_ip(from);
        terminal_write_string(": seq=");
        terminal_write_uint(seq);
        terminal_write_string(" time=");
        terminal_write_uint(rtt);
        terminal_write_string(" ms\n");
        s->received++;
        s->total += rtt;
        if (s->received == 1 || rtt < s->min) s->min = rtt;
        if (rtt > s->max) s->max = rtt;
    } else if (result == PING_UNREACHABLE) {
        terminal_write_string("Destination unreachable reported by ");
        write_ip(from);
        terminal_write_string("\n");
    } else if (result == PING_TIMEOUT) {
        terminal_write_string("Request timeout for seq=");
        terminal_write_uint(seq);
        terminal_write_string("\n");
    } else {
        terminal_write_string("Error: echo request could not be sent, no route or no ARP reply for the next hop\n");
    }
}

void net_cmd_ping(int argc, char* args[]) {
    if (argc < 2) {
        terminal_write_string("\nUsage: ping <host> [count]\n");
        return;
    }
    bool ok = true;
    uint32_t count = argc >= 3 ? parse_uint(args[2], &ok) : PING_DEFAULT_COUNT;
    ip_address_t target;
    terminal_write_string("\n");
    if (!ok || count == 0 || !resolve_or_report(args[1], &target)) return;
    terminal_write_string("PING ");
    terminal_write_string(args[1]);
    terminal_write_string(" (");
    write_ip(&target);
    terminal_write_string(")\n");

    ping_stats_t stats = {0};
    for (uint32_t seq = 1; seq <= count; seq++) {
        uint32_t start = get_system_time();
        uint32_t rtt = 0;
        ip_address_t from = {0};
        ping_result_t result = network_manager_ping_once(&target, (uint16_t)seq, PING_TIMEOUT_MS, &rtt, &from);
        stats.sent++;
        ping_report(result, (uint16_t)seq, rtt, &from, &stats);
        while (seq < count && get_system_time() - start < PING_INTERVAL_MS) network_poll();
    }
    terminal_write_uint(stats.sent);
    terminal_write_string(" sent, ");
    terminal_write_uint(stats.received);
    terminal_write_string(" received, ");
    terminal_write_uint((stats.sent - stats.received) * 100 / stats.sent);
    terminal_write_string("% loss");
    if (stats.received) {
        terminal_write_string(", rtt min/avg/max ");
        terminal_write_uint(stats.min);
        terminal_write_string("/");
        terminal_write_uint(stats.total / stats.received);
        terminal_write_string("/");
        terminal_write_uint(stats.max);
        terminal_write_string(" ms");
    }
    terminal_write_string("\n");
}

/* names and addresses */

void net_cmd_nslookup(int argc, char* args[]) {
    if (argc < 2) {
        terminal_write_string("\nUsage: nslookup <hostname|address>\n");
        return;
    }
    dns_config_t* config = dns_get_config();
    terminal_write_string("\nServer:  ");
    if (config->num_dns_servers) write_ip(&config->dns_servers[0]);
    else terminal_write_string("none configured");
    terminal_write_string("\n");
    ip_address_t ip;
    if (string_to_ip_address(args[1], &ip)) {
        char name[DNS_MAX_NAME_LENGTH + 1];
        if (!dns_reverse_lookup(&ip, name)) {
            terminal_write_string("Error: no PTR record for this address, or the query timed out\n");
            return;
        }
        terminal_write_string("Name:    ");
        terminal_write_string(name);
        terminal_write_string("\n");
        return;
    }
    if (!resolve_or_report(args[1], &ip)) return;
    terminal_write_string("Name:    ");
    terminal_write_string(args[1]);
    terminal_write_string("\nAddress: ");
    write_ip(&ip);
    terminal_write_string("\n");
}

void net_cmd_dhcp(int argc, char* args[]) {
    if (argc < 2) {
        terminal_write_string("\nUsage: dhcp <interface>\n");
        network_manager_dump_interface_info();
        return;
    }
    network_interface_t* iface = network_interface_get_by_name(args[1]);
    if (!iface) {
        terminal_write_string("\nError: no interface named '");
        terminal_write_string(args[1]);
        terminal_write_string("'\n");
        network_manager_dump_interface_info();
        return;
    }
    terminal_write_string("\nRequesting an address on ");
    terminal_write_string(iface->name);
    terminal_write_string("\n");
    if (!dhcp_start_on_interface(iface)) {
        terminal_write_string("Error: DHCP could not start, the interface has no MAC address or the socket is in use\n");
        return;
    }
    uint32_t deadline = get_system_time() + DHCP_WAIT_MS;
    while (iface->ip_addr.addr == 0 && get_system_time() < deadline) network_poll();
    if (iface->ip_addr.addr == 0) {
        terminal_set_color(12, 0);
        print_dhcp_failure(iface);
        terminal_set_color(7, 0);
        print_qemu_network_hint();
        return;
    }
    dhcp_client_t* client = dhcp_find_client(iface);
    terminal_write_string("Address: ");
    write_ip(&iface->ip_addr);
    terminal_write_string("\nNetmask: ");
    write_ip(&iface->netmask);
    terminal_write_string("\nGateway: ");
    write_ip(&iface->gateway);
    terminal_write_string("\nDNS:     ");
    write_ip(&client->lease.dns_server);
    terminal_write_string("\nLease:   ");
    terminal_write_uint(client->lease.lease_time);
    terminal_write_string(" s\n");
}

/* wget */

static bool parse_url(const char* url, char* host, uint32_t host_size, uint16_t* port, char* path, uint32_t path_size) {
    if (url[0] == 'h' && url[1] == 't' && url[2] == 't' && url[3] == 'p' && url[4] == ':' && url[5] == '/' && url[6] == '/') url += 7;
    uint32_t n = 0;
    while (*url && *url != ':' && *url != '/' && n < host_size - 1) host[n++] = *url++;
    host[n] = '\0';
    *port = HTTP_DEFAULT_PORT;
    if (*url == ':') {
        uint32_t value = 0;
        for (url++; *url >= '0' && *url <= '9'; url++) value = value * 10 + (uint32_t)(*url - '0');
        if (value == 0 || value > ECHO_PORT_MAX) return false;
        *port = (uint16_t)value;
    }
    string_copy_n(path, *url == '/' ? url : "/", path_size);
    return n > 0;
}

static uint8_t wget_buffer[WGET_BUFFER];

static void wget_save(const char* file, uint32_t length) {
    if (filesystem_file_exists(file)) filesystem_delete_file(file);
    fs_file_handle_t* handle = filesystem_create_file(file) ? filesystem_open_file(file, true) : NULL;
    uint32_t written = handle ? filesystem_write_file(handle, wget_buffer, length) : 0;
    if (handle) filesystem_close_file(handle);
    if (written != length) {
        terminal_write_string("Error: could not write ");
        terminal_write_string(file);
        terminal_write_string("\n");
        return;
    }
    terminal_write_string("Saved to ");
    terminal_write_string(file);
    terminal_write_string("\n");
}

static void wget_preview(uint32_t length) {
    uint32_t shown = length < WGET_PREVIEW ? length : WGET_PREVIEW;
    for (uint32_t i = 0; i < shown; i++) {
        char c = (char)wget_buffer[i];
        if ((c >= 32 && c <= 126) || c == '\n') terminal_write_char(c);
    }
    if (length > shown) {
        terminal_write_string("\n(");
        terminal_write_uint(length - shown);
        terminal_write_string(" more bytes, give a file name to keep all of it)");
    }
    terminal_write_string("\n");
}

void net_cmd_wget(int argc, char* args[]) {
    char host[DNS_MAX_NAME_LENGTH + 1];
    char path[256];
    uint16_t port;
    if (argc < 2 || !parse_url(args[1], host, sizeof(host), &port, path, sizeof(path))) {
        terminal_write_string("\nUsage: wget <http://host[:port]/path> [file]\n");
        return;
    }
    http_result_t result;
    terminal_write_string("\n");
    if (!network_manager_http_get(host, port, path, wget_buffer, sizeof(wget_buffer), &result)) {
        terminal_set_color(12, 0);
        terminal_write_string("Error: ");
        terminal_write_string(result.error);
        terminal_write_string("\n");
        terminal_set_color(7, 0);
        return;
    }
    terminal_write_string("HTTP ");
    terminal_write_int(result.status_code);
    terminal_write_string(", ");
    terminal_write_uint(result.body_bytes);
    terminal_write_string(" bytes of body");
    if (result.truncated) {
        terminal_write_string(", truncated at ");
        terminal_write_uint(WGET_BUFFER);
        terminal_write_string(" bytes");
    }
    terminal_write_string("\n");
    if (argc >= 3) wget_save(args[2], result.body_bytes);
    else wget_preview(result.body_bytes);
}

/* telnet */

// Refuses every option the server asks about, which leaves a plain character stream
static uint32_t telnet_filter(tcp_socket_t* socket, uint8_t* data, uint32_t length) {
    uint32_t out = 0;
    for (uint32_t i = 0; i < length; i++) {
        if (data[i] != TELNET_IAC || i + 1 >= length) {
            if (data[i] != '\r') data[out++] = data[i];
            continue;
        }
        uint8_t command = data[i + 1];
        if ((command == TELNET_DO || command == TELNET_WILL) && i + 2 < length) {
            uint8_t reply[3] = {TELNET_IAC, command == TELNET_DO ? TELNET_WONT : TELNET_DONT, data[i + 2]};
            tcp_send(socket, reply, sizeof(reply));
            i += 2;
        } else if (command == TELNET_SB) {
            while (i + 1 < length && !(data[i] == TELNET_IAC && data[i + 1] == TELNET_SE)) i++;
            i++;
        } else {
            i += (command == TELNET_DONT || command == TELNET_WONT) ? 2 : 1;
        }
    }
    return out;
}

static bool telnet_keyboard(tcp_socket_t* socket) {
    if (!input_manager_has_input()) return true;
    char c = input_manager_scancode_to_ascii(input_manager_read_scancode());
    if (c == ASCII_ESCAPE) return false;
    if (c == '\n' || c == '\r') {
        tcp_send(socket, "\r\n", 2);
        terminal_write_char('\n');
    } else if (c) {
        tcp_send(socket, &c, 1);
        terminal_write_char(c);
    }
    return true;
}

void net_cmd_telnet(int argc, char* args[]) {
    bool ok = true;
    uint32_t port = argc >= 3 ? parse_uint(args[2], &ok) : 23;
    if (argc < 2 || !ok || port == 0 || port > ECHO_PORT_MAX) {
        terminal_write_string("\nUsage: telnet <host> [port], Esc closes the connection\n");
        return;
    }
    ip_address_t ip;
    terminal_write_string("\n");
    if (!resolve_or_report(args[1], &ip)) return;
    tcp_socket_t* socket = tcp_create_socket();
    if (!socket || !tcp_connect(socket, &ip, (uint16_t)port)) {
        terminal_write_string("Error: connection to ");
        write_ip(&ip);
        terminal_write_string(" refused or timed out\n");
        if (socket) tcp_close(socket);
        return;
    }
    terminal_write_string("Connected, press Esc to close\n");
    uint8_t buffer[512];
    while (telnet_keyboard(socket)) {
        network_poll();
        int32_t n = tcp_receive(socket, buffer, sizeof(buffer));
        if (n < 0) {
            terminal_write_string("\nConnection closed by the remote host\n");
            break;
        }
        uint32_t length = telnet_filter(socket, buffer, (uint32_t)n);
        for (uint32_t i = 0; i < length; i++) terminal_write_char((char)buffer[i]);
    }
    tcp_close(socket);
}

/* traceroute */

void net_cmd_traceroute(int argc, char* args[]) {
    ip_address_t target;
    if (argc < 2) {
        terminal_write_string("\nUsage: traceroute <host>\n");
        return;
    }
    terminal_write_string("\n");
    if (!resolve_or_report(args[1], &target)) return;
    terminal_write_string("traceroute to ");
    write_ip(&target);
    terminal_write_string(", 30 hops max, any key stops\n");
    for (uint8_t ttl = 1; ttl <= TRACE_MAX_HOPS; ttl++) {
        terminal_write_uint(ttl);
        terminal_write_string(ttl < 10 ? "   " : "  ");
        uint32_t start = get_system_time();
        icmp_event_t event;
        if (!icmp_send_echo_ttl(&target, ttl, TRACE_IDENTIFIER, ttl)) {
            terminal_write_string("send failed, no route\n");
            return;
        }
        if (!icmp_wait_event(TRACE_IDENTIFIER, ttl, TRACE_TIMEOUT_MS, &event)) {
            terminal_write_string("*\n");
        } else {
            write_ip(&event.from);
            terminal_write_string("  ");
            terminal_write_uint(event.time_ms - start);
            terminal_write_string(" ms\n");
            if (event.type == ICMP_TYPE_ECHO_REPLY || event.type == ICMP_TYPE_DEST_UNREACHABLE) return;
        }
        if (key_pressed()) return;
    }
}

/* tcpdump */

static uint16_t be16_at(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void dump_transport(const uint8_t* ip, uint32_t length) {
    uint32_t header = (ip[0] & 0x0F) * 4u;
    const uint8_t* t = ip + header;
    if (header + 4 > length) return;
    if (ip[9] == IP_PROTOCOL_ICMP) {
        terminal_write_string(" ICMP type ");
        terminal_write_uint(t[0]);
        return;
    }
    terminal_write_string(ip[9] == IP_PROTOCOL_TCP ? " TCP " : (ip[9] == IP_PROTOCOL_UDP ? " UDP " : " proto "));
    terminal_write_uint(be16_at(t));
    terminal_write_string(" > ");
    terminal_write_uint(be16_at(t + 2));
    if (ip[9] == IP_PROTOCOL_TCP && header + 14 <= length) {
        static const char names[] = "FSRPAU";
        terminal_write_string(" [");
        for (int bit = 0; bit < 6; bit++) if (t[13] & (1 << bit)) terminal_write_char(names[bit]);
        terminal_write_string("]");
    }
}

static void dump_frame(const net_capture_entry_t* e) {
    terminal_write_uint(e->time_ms);
    terminal_write_string(e->outbound ? " out " : " in  ");
    uint16_t type = e->length >= ETH_HEADER ? be16_at(&e->data[12]) : 0;
    const uint8_t* p = e->data + ETH_HEADER;
    if (type == ETHERTYPE_ARP && e->length >= ETH_HEADER + 28) {
        terminal_write_string(be16_at(p + 6) == ARP_OPERATION_REQUEST ? "ARP who-has " : "ARP reply ");
        write_ip((const ip_address_t*)(p + 24));
        terminal_write_string(" tell ");
        write_ip((const ip_address_t*)(p + 14));
    } else if (type == ETHERTYPE_IP && e->length >= ETH_HEADER + IP_HEADER_MIN_SIZE) {
        terminal_write_string("IP ");
        write_ip((const ip_address_t*)(p + 12));
        terminal_write_string(" > ");
        write_ip((const ip_address_t*)(p + 16));
        uint32_t captured = e->length < NET_CAPTURE_BYTES ? e->length : NET_CAPTURE_BYTES;
        dump_transport(p, captured - ETH_HEADER);
    } else {
        terminal_write_string("ethertype ");
        terminal_write_hex(type);
    }
    terminal_write_string(" len ");
    terminal_write_uint(e->length);
    terminal_write_string("\n");
}

void net_cmd_tcpdump(int argc, char* args[]) {
    bool ok = true;
    uint32_t count = argc >= 2 ? parse_uint(args[1], &ok) : TCPDUMP_DEFAULT_COUNT;
    if (!ok || count == 0) {
        terminal_write_string("\nUsage: tcpdump [count], any key stops\n");
        return;
    }
    terminal_write_string("\nCapturing on all interfaces, any key stops\n");
    network_capture_enable(true);
    uint32_t shown = 0;
    net_capture_entry_t entry;
    while (shown < count && !key_pressed()) {
        network_poll();
        while (shown < count && network_capture_next(&entry)) {
            dump_frame(&entry);
            shown++;
        }
    }
    uint32_t dropped = network_capture_dropped();
    network_capture_enable(false);
    terminal_write_uint(shown);
    terminal_write_string(" frames shown, ");
    terminal_write_uint(dropped);
    terminal_write_string(" dropped because the capture ring was full\n");
}

/* route and arp */

static bool parse_prefix(const char* text, ip_address_t* network, ip_address_t* netmask) {
    char address[16];
    uint32_t i = 0;
    while (text[i] && text[i] != '/' && i < sizeof(address) - 1) { address[i] = text[i]; i++; }
    address[i] = '\0';
    if (!string_to_ip_address(address, network)) return false;
    bool ok = true;
    uint32_t prefix = text[i] == '/' ? parse_uint(&text[i + 1], &ok) : IPV4_BITS;
    if (!ok || prefix > IPV4_BITS) return false;
    netmask->addr = __builtin_bswap32(prefix ? 0xFFFFFFFFu << (IPV4_BITS - prefix) : 0);
    return true;
}

void net_cmd_route(int argc, char* args[]) {
    ip_address_t network, netmask, gateway = {0};
    if (argc < 2 || string_equals(args[1], "show")) {
        terminal_write_string("\n");
        network_manager_dump_routing_table();
        return;
    }
    if (string_equals(args[1], "add") && argc >= 4 && parse_prefix(args[2], &network, &netmask)) {
        network_interface_t* iface = argc >= 5 ? network_interface_get_by_name(args[4]) : network_interface_get_default();
        bool direct = string_equals(args[3], "direct");
        if (!iface || (!direct && !string_to_ip_address(args[3], &gateway))) {
            terminal_write_string("\nError: unknown interface or bad gateway address\n");
        } else {
            terminal_write_string(ip_route_add(&network, &netmask, direct ? NULL : &gateway, iface)
                                  ? "\nRoute added\n" : "\nError: routing table is full\n");
        }
        return;
    }
    if (string_equals(args[1], "del") && argc >= 3 && parse_prefix(args[2], &network, &netmask)) {
        terminal_write_string(ip_route_delete(&network, &netmask) ? "\nRoute deleted\n" : "\nError: no such static route\n");
        return;
    }
    terminal_write_string("\nUsage: route show\n       route add <net/prefix> <gateway|direct> [iface]\n       route del <net/prefix>\n");
}

void net_cmd_arp(int argc, char* args[]) {
    terminal_write_string("\n");
    if (argc >= 2 && string_equals(args[1], "clear")) {
        arp_clear_table();
        terminal_write_string("ARP table cleared\n");
    } else if (argc < 2 || string_equals(args[1], "show")) {
        arp_dump_table();
    } else {
        terminal_write_string("Usage: arp <show|clear>\n");
    }
}

/* netstat */

void net_cmd_netstat(int argc, char* args[]) {
    (void)argc;
    (void)args;
    terminal_write_string("\nProto  Local                  Remote                 State\n");
    tcp_connection_info_t connections[TCP_MAX_CONNECTIONS];
    uint32_t count = tcp_list_connections(connections, TCP_MAX_CONNECTIONS);
    for (uint32_t i = 0; i < count; i++) {
        write_padded("tcp", 7);
        write_endpoint(&connections[i].local_ip, connections[i].local_port, 23);
        write_endpoint(&connections[i].remote_ip, connections[i].remote_port, 23);
        terminal_write_string(tcp_state_name(connections[i].state));
        terminal_write_string("\n");
    }
    uint16_t ports[UDP_MAX_PORTS];
    uint32_t udp = udp_list_bound_ports(ports, UDP_MAX_PORTS);
    ip_address_t any = {0};
    for (uint32_t i = 0; i < udp; i++) {
        write_padded("udp", 7);
        write_endpoint(&any, ports[i], 23);
        terminal_write_string("*\n");
    }
    network_statistics_t* ip = network_get_statistics();
    tcp_statistics_t* tcp = tcp_get_statistics();
    terminal_write_string("IP in ");
    terminal_write_uint((uint32_t)ip->ip_packets_received);
    terminal_write_string(" out ");
    terminal_write_uint((uint32_t)ip->ip_packets_sent);
    terminal_write_string(" dropped ");
    terminal_write_uint((uint32_t)ip->ip_packets_dropped);
    terminal_write_string(" fragments dropped ");
    terminal_write_uint((uint32_t)ip->ip_fragments_dropped);
    if (tcp) {
        terminal_write_string("\nTCP segments in ");
        terminal_write_uint((uint32_t)tcp->segments_received);
        terminal_write_string(" out ");
        terminal_write_uint((uint32_t)tcp->segments_sent);
        terminal_write_string(" retransmitted ");
        terminal_write_uint((uint32_t)tcp->segments_retransmitted);
        terminal_write_string(" resets sent ");
        terminal_write_uint((uint32_t)tcp->resets_sent);
    }
    terminal_write_string("\nUDP in ");
    terminal_write_uint((uint32_t)ip->udp_packets_received);
    terminal_write_string(" out ");
    terminal_write_uint((uint32_t)ip->udp_packets_sent);
    terminal_write_string(" no port ");
    terminal_write_uint((uint32_t)ip->udp_no_port);
    terminal_write_string("\n");
}

/* listen */

static uint32_t echo_handler(const ip_address_t* client_ip, const void* data, uint32_t length,
                             uint8_t* reply, uint32_t reply_size) {
    (void)client_ip;
    uint32_t n = length < reply_size ? length : reply_size;
    const uint8_t* in = (const uint8_t*)data;
    for (uint32_t i = 0; i < n; i++) reply[i] = in[i];
    return n;
}

void net_cmd_listen(int argc, char* args[]) {
    bool ok = true;
    bool stop = argc >= 3 && string_equals(args[1], "stop");
    uint32_t port = argc >= 2 ? parse_uint(stop ? args[2] : args[1], &ok) : 0;
    if (argc < 2 || !ok || port == 0 || port > ECHO_PORT_MAX) {
        terminal_write_string("\nUsage: listen <port>       start a TCP echo service\n       listen stop <port>\n");
        return;
    }
    if (stop) {
        terminal_write_string(network_manager_stop_service((uint16_t)port) ? "\nService stopped\n" : "\nError: nothing listens on that port\n");
        return;
    }
    if (!network_manager_start_service((uint16_t)port, echo_handler)) {
        terminal_write_string("\nError: port in use, no free service slot or no free TCP socket\n");
        return;
    }
    terminal_write_string("\nEcho service listening on TCP port ");
    terminal_write_uint(port);
    terminal_write_string("\n");
}
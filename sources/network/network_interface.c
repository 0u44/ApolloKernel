#include "network_interface.h"
#include "heap_allocator.h"
#include "time_keeper.h"
#include "terminal.h"
#include "string_utils.h"
#include "types.h"

#define ETH_HEADER_SIZE 14
#define CAPTURE_SLOTS 64
#define RX_BURST 32

extern void ip_process_packet(network_interface_t* iface, const void* packet, uint32_t length);
extern void arp_process_packet(network_interface_t* iface, const void* packet, uint32_t length);

static struct {
    network_interface_t interfaces[NET_MAX_INTERFACES];
    uint32_t interface_count;
    uint32_t next_interface_id;
    bool is_initialized;
} net_manager = {0};

static struct {
    net_capture_entry_t entries[CAPTURE_SLOTS];
    uint32_t head;
    uint32_t tail;
    uint32_t dropped;
    bool enabled;
} capture = {0};

void network_interface_manager_initialize(void) {
    if (net_manager.is_initialized) return;
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        net_manager.interfaces[i].is_active = false;
    }
    net_manager.interface_count = 0;
    net_manager.next_interface_id = 1;
    net_manager.is_initialized = true;
}

network_interface_t* network_interface_register(const char* name,
    bool (*send_fn)(network_interface_t*, const void*, uint32_t),
    bool (*receive_fn)(network_interface_t*, void*, uint32_t*),
    void* driver_data) {
    network_interface_manager_initialize();
    if (!name || !send_fn) return NULL;
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        network_interface_t* iface = &net_manager.interfaces[i];
        if (iface->is_active) continue;
        uint8_t* bytes = (uint8_t*)iface;
        for (uint32_t b = 0; b < sizeof(*iface); b++) bytes[b] = 0;
        iface->interface_id = net_manager.next_interface_id++;
        string_copy_n(iface->name, name, sizeof(iface->name));
        iface->state = NET_INTERFACE_DOWN;
        iface->send_packet = send_fn;
        iface->receive_packet = receive_fn;
        iface->driver_data = driver_data;
        iface->is_active = true;
        net_manager.interface_count++;
        return iface;
    }
    return NULL;
}

bool network_interface_unregister(uint32_t interface_id) {
    network_interface_t* iface = network_interface_get_by_id(interface_id);
    if (!iface) return false;
    iface->is_active = false;
    iface->state = NET_INTERFACE_DOWN;
    net_manager.interface_count--;
    return true;
}

network_interface_t* network_interface_get_by_id(uint32_t interface_id) {
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        if (net_manager.interfaces[i].is_active && net_manager.interfaces[i].interface_id == interface_id) {
            return &net_manager.interfaces[i];
        }
    }
    return NULL;
}

network_interface_t* network_interface_get_by_name(const char* name) {
    if (!name) return NULL;
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        if (net_manager.interfaces[i].is_active && string_equals(net_manager.interfaces[i].name, name)) {
            return &net_manager.interfaces[i];
        }
    }
    return NULL;
}

// Prefers an interface that is up and configured, then any interface that is up
network_interface_t* network_interface_get_default(void) {
    network_interface_t* up = NULL;
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        network_interface_t* iface = &net_manager.interfaces[i];
        if (!iface->is_active || iface->state != NET_INTERFACE_UP) continue;
        if (iface->ip_addr.addr != 0) return iface;
        if (!up) up = iface;
    }
    return up;
}

uint32_t network_interface_count(void) {
    return net_manager.interface_count;
}

bool network_interface_set_mac_address(uint32_t interface_id, const mac_address_t* mac) {
    network_interface_t* iface = network_interface_get_by_id(interface_id);
    if (!iface || !mac) return false;
    mac_address_copy(&iface->mac_addr, mac);
    return true;
}

bool network_interface_set_ip_config(uint32_t interface_id, ip_address_t ip, ip_address_t netmask, ip_address_t gateway) {
    network_interface_t* iface = network_interface_get_by_id(interface_id);
    if (!iface) return false;
    iface->ip_addr = ip;
    iface->netmask = netmask;
    iface->gateway = gateway;
    return true;
}

bool network_interface_bring_up(uint32_t interface_id) {
    network_interface_t* iface = network_interface_get_by_id(interface_id);
    if (!iface) return false;
    mac_address_t zero = {{0}};
    if (mac_address_equals(&iface->mac_addr, &zero)) return false;
    iface->state = NET_INTERFACE_UP;
    return true;
}

bool network_interface_bring_down(uint32_t interface_id) {
    network_interface_t* iface = network_interface_get_by_id(interface_id);
    if (!iface) return false;
    iface->state = NET_INTERFACE_DOWN;
    return true;
}

/* packet capture */

static void capture_frame(const uint8_t* frame, uint32_t length, bool outbound) {
    if (!capture.enabled) return;
    uint32_t next = (capture.head + 1) % CAPTURE_SLOTS;
    if (next == capture.tail) {
        capture.dropped++;
        return;
    }
    net_capture_entry_t* e = &capture.entries[capture.head];
    e->time_ms = (uint32_t)time_keeper_get_uptime_ms();
    e->outbound = outbound;
    e->length = (uint16_t)length;
    uint32_t keep = length < NET_CAPTURE_BYTES ? length : NET_CAPTURE_BYTES;
    for (uint32_t i = 0; i < keep; i++) e->data[i] = frame[i];
    capture.head = next;
}

void network_capture_enable(bool enable) {
    capture.enabled = enable;
    capture.head = 0;
    capture.tail = 0;
    capture.dropped = 0;
}

bool network_capture_next(net_capture_entry_t* entry) {
    if (capture.tail == capture.head || !entry) return false;
    *entry = capture.entries[capture.tail];
    capture.tail = (capture.tail + 1) % CAPTURE_SLOTS;
    return true;
}

uint32_t network_capture_dropped(void) {
    return capture.dropped;
}

/* frames */

bool network_interface_send_ethernet_frame(network_interface_t* iface,
    const mac_address_t* dst_mac, uint16_t ethertype, const void* payload, uint32_t payload_length) {
    if (!iface || !dst_mac || !payload || payload_length == 0 || payload_length > NET_MTU_SIZE) return false;
    if (iface->state != NET_INTERFACE_UP || !iface->send_packet) return false;

    uint8_t frame[ETH_HEADER_SIZE + NET_MTU_SIZE];
    for (int i = 0; i < NET_MAC_ADDR_LEN; i++) {
        frame[i] = dst_mac->addr[i];
        frame[NET_MAC_ADDR_LEN + i] = iface->mac_addr.addr[i];
    }
    frame[12] = (uint8_t)(ethertype >> 8);
    frame[13] = (uint8_t)ethertype;
    const uint8_t* bytes = (const uint8_t*)payload;
    for (uint32_t i = 0; i < payload_length; i++) frame[ETH_HEADER_SIZE + i] = bytes[i];

    uint32_t total = ETH_HEADER_SIZE + payload_length;
    capture_frame(frame, total, true);
    if (!iface->send_packet(iface, frame, total)) {
        iface->tx_errors++;
        return false;
    }
    iface->tx_packets++;
    iface->tx_bytes += total;
    return true;
}

uint32_t network_interface_list_all(network_interface_t** interfaces, uint32_t max_count) {
    if (!interfaces) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < NET_MAX_INTERFACES && count < max_count; i++) {
        if (net_manager.interfaces[i].is_active) interfaces[count++] = &net_manager.interfaces[i];
    }
    return count;
}

static void dispatch_frame(network_interface_t* iface, uint8_t* frame, uint32_t length) {
    const ethernet_frame_t* eth = (const ethernet_frame_t*)frame;
    if (!mac_address_is_broadcast(&eth->dst_mac) && !mac_address_is_multicast(&eth->dst_mac) &&
        !mac_address_equals(&eth->dst_mac, &iface->mac_addr)) {
        return;
    }
    uint16_t ethertype = (uint16_t)((frame[12] << 8) | frame[13]);
    if (ethertype == ETHERTYPE_IP) ip_process_packet(iface, frame + ETH_HEADER_SIZE, length - ETH_HEADER_SIZE);
    else if (ethertype == ETHERTYPE_ARP) arp_process_packet(iface, frame + ETH_HEADER_SIZE, length - ETH_HEADER_SIZE);
}

// Drains up to a burst of frames per interface so one busy card cannot starve the loop
void network_interface_process_incoming_packets(void) {
    uint8_t frame[NET_MAX_PACKET_SIZE];
    for (uint32_t i = 0; i < NET_MAX_INTERFACES; i++) {
        network_interface_t* iface = &net_manager.interfaces[i];
        if (!iface->is_active || iface->state != NET_INTERFACE_UP || !iface->receive_packet) continue;
        for (uint32_t n = 0; n < RX_BURST; n++) {
            uint32_t length = sizeof(frame);
            if (!iface->receive_packet(iface, frame, &length)) break;
            if (length < ETH_HEADER_SIZE) {
                iface->rx_errors++;
                continue;
            }
            iface->rx_packets++;
            iface->rx_bytes += length;
            capture_frame(frame, length, false);
            dispatch_frame(iface, frame, length);
        }
    }
}

/* address helpers */

bool mac_address_equals(const mac_address_t* mac1, const mac_address_t* mac2) {
    if (!mac1 || !mac2) return false;
    for (int i = 0; i < NET_MAC_ADDR_LEN; i++) {
        if (mac1->addr[i] != mac2->addr[i]) return false;
    }
    return true;
}

bool mac_address_is_broadcast(const mac_address_t* mac) {
    if (!mac) return false;
    for (int i = 0; i < NET_MAC_ADDR_LEN; i++) {
        if (mac->addr[i] != 0xFF) return false;
    }
    return true;
}

bool mac_address_is_multicast(const mac_address_t* mac) {
    return mac && (mac->addr[0] & 0x01) != 0;
}

void mac_address_copy(mac_address_t* dst, const mac_address_t* src) {
    if (!dst || !src) return;
    for (int i = 0; i < NET_MAC_ADDR_LEN; i++) dst->addr[i] = src->addr[i];
}

void mac_address_to_string(const mac_address_t* mac, char* buffer) {
    if (!mac || !buffer) return;
    const char* hex = "0123456789ABCDEF";
    int pos = 0;
    for (int i = 0; i < NET_MAC_ADDR_LEN; i++) {
        buffer[pos++] = hex[mac->addr[i] >> 4];
        buffer[pos++] = hex[mac->addr[i] & 0xF];
        if (i < NET_MAC_ADDR_LEN - 1) buffer[pos++] = ':';
    }
    buffer[pos] = '\0';
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

bool string_to_mac_address(const char* str, mac_address_t* mac) {
    if (!str || !mac) return false;
    for (int i = 0; i < NET_MAC_ADDR_LEN; i++) {
        int high = hex_value(str[0]);
        int low = high < 0 ? -1 : hex_value(str[1]);
        if (low < 0) return false;
        mac->addr[i] = (uint8_t)((high << 4) | low);
        str += 2;
        if (i < NET_MAC_ADDR_LEN - 1 && *str++ != ':') return false;
    }
    return *str == '\0';
}

// Addresses are kept in network byte order, so the first octet is the lowest byte in memory
bool ip_address_equals(const ip_address_t* ip1, const ip_address_t* ip2) {
    return ip1 && ip2 && ip1->addr == ip2->addr;
}

bool ip_address_is_broadcast(const ip_address_t* ip, const ip_address_t* netmask) {
    return ip && netmask && (ip->addr | ~netmask->addr) == 0xFFFFFFFF;
}

bool ip_address_is_in_subnet(const ip_address_t* ip, const ip_address_t* network, const ip_address_t* netmask) {
    return ip && network && netmask && (ip->addr & netmask->addr) == (network->addr & netmask->addr);
}

void ip_address_to_string(const ip_address_t* ip, char* buffer) {
    if (!ip || !buffer) return;
    const uint8_t* octets = (const uint8_t*)&ip->addr;
    int pos = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t value = octets[i];
        if (value >= 100) buffer[pos++] = (char)('0' + value / 100);
        if (value >= 10) buffer[pos++] = (char)('0' + (value / 10) % 10);
        buffer[pos++] = (char)('0' + value % 10);
        if (i < 3) buffer[pos++] = '.';
    }
    buffer[pos] = '\0';
}

bool string_to_ip_address(const char* str, ip_address_t* ip) {
    if (!str || !ip) return false;
    uint8_t octets[4];
    for (int i = 0; i < 4; i++) {
        uint32_t value = 0;
        int digits = 0;
        while (*str >= '0' && *str <= '9' && digits < 4) {
            value = value * 10 + (uint32_t)(*str++ - '0');
            digits++;
        }
        if (digits == 0 || value > 255) return false;
        octets[i] = (uint8_t)value;
        if (i < 3 && *str++ != '.') return false;
    }
    if (*str != '\0') return false;
    uint8_t* out = (uint8_t*)&ip->addr;
    for (int i = 0; i < 4; i++) out[i] = octets[i];
    return true;
}

uint16_t network_checksum(const void* data, uint32_t length) {
    return network_checksum_partial(0, data, length);
}

// The initial value is the folded but uncomplemented sum of earlier parts
uint16_t network_checksum_partial(uint16_t initial, const void* data, uint32_t length) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t sum = initial;
    while (length > 1) {
        sum += (uint32_t)(bytes[0] | (bytes[1] << 8));
        bytes += 2;
        length -= 2;
    }
    if (length > 0) sum += bytes[0];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}
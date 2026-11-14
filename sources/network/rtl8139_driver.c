#include "rtl8139_driver.h"
#include "network_interface.h"
#include "terminal.h"
#include "heap_allocator.h"
#include "time_keeper.h"
#include "types.h"

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA 0xCFC
#define PCI_ENABLE_BIT 0x80000000u
#define PCI_COMMAND 0x04
#define PCI_COMMAND_IO_AND_MASTER 0x05
#define PCI_BAR0 0x10
#define PCI_INTERRUPT_LINE 0x3C
#define PCI_IO_BAR_FLAG 0x01
#define PCI_MAX_BUS 256
#define PCI_NO_DEVICE 0xFFFF

#define RTL_MAX_DEVICES 4
#define RTL_RESET_POLL_US 10
#define RTL_RESET_POLLS 10000
#define RTL_TX_OWN 0x2000      // Set by the chip when the descriptor is free again
#define RTL_TX_TOK 0x8000
#define RTL_TX_POLLS 10000
#define RTL_RX_ROK 0x0001
#define RTL_RX_HEADER 4
#define RTL_CRC_SIZE 4
#define RTL_CAPR_OFFSET 16
#define RTL_MIN_FRAME 60
#define RTL_MAX_FRAME 1518
#define RTL_MSR_LINK_DOWN 0x04
#define RTL_CONFIG1_POWER_ON 0x00

static rtl8139_device_t* rtl8139_devices[RTL_MAX_DEVICES] = {NULL};
static uint32_t device_count = 0;

static inline void outb(uint16_t port, uint8_t data) {
    __asm__ volatile("outb %0, %1" : : "a"(data), "Nd"(port));
}

static inline void outw(uint16_t port, uint16_t data) {
    __asm__ volatile("outw %0, %1" : : "a"(data), "Nd"(port));
}

static inline void outl(uint16_t port, uint32_t data) {
    __asm__ volatile("outl %0, %1" : : "a"(data), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t result;
    __asm__ volatile("inb %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static inline uint16_t inw(uint16_t port) {
    uint16_t result;
    __asm__ volatile("inw %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static inline uint32_t inl(uint16_t port) {
    uint32_t result;
    __asm__ volatile("inl %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static void copy_bytes(void* dest, const void* src, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < size; i++) d[i] = s[i];
}

static void zero_bytes(void* dest, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) d[i] = 0;
}

/* PCI configuration space, shared with the other drivers */

static uint32_t config_address(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    return PCI_ENABLE_BIT | ((uint32_t)bus << 16) | ((uint32_t)device << 11) |
           ((uint32_t)function << 8) | (offset & 0xFC);
}

uint32_t pci_read_config_dword(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    outl(PCI_CONFIG_ADDRESS, config_address(bus, device, function, offset));
    return inl(PCI_CONFIG_DATA);
}

uint16_t pci_read_config_word(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    return (uint16_t)(pci_read_config_dword(bus, device, function, offset) >> ((offset & 2) * 8));
}

uint8_t pci_read_config_byte(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    return (uint8_t)(pci_read_config_dword(bus, device, function, offset) >> ((offset & 3) * 8));
}

void pci_write_config_dword(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint32_t value) {
    outl(PCI_CONFIG_ADDRESS, config_address(bus, device, function, offset));
    outl(PCI_CONFIG_DATA, value);
}

static void write_config_bits(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset,
                              uint32_t value, uint32_t width_mask) {
    uint32_t shift = (offset & 3) * 8;
    uint32_t current = pci_read_config_dword(bus, device, function, offset);
    uint32_t mask = width_mask << shift;
    pci_write_config_dword(bus, device, function, offset, (current & ~mask) | ((value & width_mask) << shift));
}

void pci_write_config_word(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint16_t value) {
    write_config_bits(bus, device, function, offset & 0xFE, value, 0xFFFF);
}

void pci_write_config_byte(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint8_t value) {
    write_config_bits(bus, device, function, offset, value, 0xFF);
}

// Probes every matching card and returns true if at least one came up
bool pci_scan_for_devices(uint16_t vendor_id, uint16_t device_id) {
    bool found = false;
    for (uint16_t bus = 0; bus < PCI_MAX_BUS; bus++) {
        for (uint16_t device = 0; device < 32; device++) {
            for (uint16_t function = 0; function < 8; function++) {
                uint16_t vendor = pci_read_config_word(bus, device, function, 0x00);
                if (vendor == PCI_NO_DEVICE) {
                    if (function == 0) break;
                    continue;
                }
                if (vendor == vendor_id && pci_read_config_word(bus, device, function, 0x02) == device_id) {
                    found |= rtl8139_probe_and_initialize_device(bus, device, function);
                }
            }
        }
    }
    return found;
}

/* chip control */

void rtl8139_reset(rtl8139_device_t* device) {
    if (!device) return;
    outb(device->io_base + RTL8139_CONFIG1, RTL_CONFIG1_POWER_ON);
    outb(device->io_base + RTL8139_CR, RTL8139_CR_RST);
    for (uint32_t i = 0; i < RTL_RESET_POLLS && (inb(device->io_base + RTL8139_CR) & RTL8139_CR_RST); i++) {
        time_keeper_delay_us(RTL_RESET_POLL_US);
    }
    device->rx_current = 0;
    device->tx_current = 0;
}

void rtl8139_get_mac_address(rtl8139_device_t* device, mac_address_t* mac) {
    if (!device || !mac) return;
    for (int i = 0; i < NET_MAC_ADDR_LEN; i++) {
        mac->addr[i] = inb(device->io_base + RTL8139_IDR0 + i);
    }
}

bool rtl8139_link_up(rtl8139_device_t* device) {
    return device && !(inb(device->io_base + RTL8139_MSR) & RTL_MSR_LINK_DOWN);
}

static bool allocate_buffers(rtl8139_device_t* device) {
    device->rx_buffer_raw = apollo_allocate_memory(RTL8139_RX_BUFFER_SIZE + RTL8139_RX_SLACK + 16);
    if (!device->rx_buffer_raw) return false;
    device->rx_buffer = (uint8_t*)(((uintptr_t)device->rx_buffer_raw + 15) & ~(uintptr_t)15);
    device->rx_buffer_phys = (uint32_t)(uintptr_t)device->rx_buffer;
    zero_bytes(device->rx_buffer, RTL8139_RX_BUFFER_SIZE + RTL8139_RX_SLACK);
    for (int i = 0; i < RTL8139_NUM_TX_DESC; i++) {
        device->tx_buffer[i] = apollo_allocate_memory(RTL8139_TX_BUFFER_SIZE);
        if (!device->tx_buffer[i]) return false;
        device->tx_buffer_phys[i] = (uint32_t)(uintptr_t)device->tx_buffer[i];
    }
    return true;
}

static void free_buffers(rtl8139_device_t* device) {
    if (device->rx_buffer_raw) apollo_free_memory(device->rx_buffer_raw);
    for (int i = 0; i < RTL8139_NUM_TX_DESC; i++) {
        if (device->tx_buffer[i]) apollo_free_memory(device->tx_buffer[i]);
    }
}

// Interrupts stay masked, the network task polls CR.BUFE instead
static void configure(rtl8139_device_t* device) {
    uint16_t io = device->io_base;
    outl(io + RTL8139_RXBUF, device->rx_buffer_phys);
    for (int i = 0; i < RTL8139_NUM_TX_DESC; i++) {
        outl(io + RTL8139_TXADDR0 + i * 4, device->tx_buffer_phys[i]);
    }
    outw(io + RTL8139_IMR, 0);
    outw(io + RTL8139_ISR, 0xFFFF);
    outb(io + RTL8139_CR, RTL8139_CR_RE | RTL8139_CR_TE);
    outl(io + RTL8139_RCR, RTL8139_RCR_APM | RTL8139_RCR_AM | RTL8139_RCR_AB | RTL8139_RCR_WRAP |
                           RTL8139_RCR_RBLEN_8K | RTL8139_RCR_MXDMA_UNLIMITED | RTL8139_RCR_RXFTH_NO_THRESH);
    outl(io + RTL8139_TCR, RTL8139_TCR_IFG96 | RTL8139_TCR_MXDMA_2048);
    outw(io + RTL8139_CAPR, (uint16_t)(0 - RTL_CAPR_OFFSET));
}

static void restart_receiver(rtl8139_device_t* device) {
    uint16_t io = device->io_base;
    outb(io + RTL8139_CR, RTL8139_CR_TE);
    device->rx_current = 0;
    outl(io + RTL8139_RXBUF, device->rx_buffer_phys);
    outb(io + RTL8139_CR, RTL8139_CR_RE | RTL8139_CR_TE);
    outw(io + RTL8139_CAPR, (uint16_t)(0 - RTL_CAPR_OFFSET));
}

/* data path */

bool rtl8139_send_packet(network_interface_t* iface, const void* packet, uint32_t length) {
    rtl8139_device_t* device = iface ? (rtl8139_device_t*)iface->driver_data : NULL;
    if (!device || !packet || length == 0 || length > RTL_MAX_FRAME - RTL_CRC_SIZE) return false;

    uint8_t slot = device->tx_current;
    uint16_t status_port = device->io_base + RTL8139_TXSTATUS0 + slot * 4;
    uint32_t polls = 0;
    while (!(inl(status_port) & RTL_TX_OWN) && polls++ < RTL_TX_POLLS) time_keeper_delay_us(1);
    if (!(inl(status_port) & RTL_TX_OWN)) {
        device->tx_errors++;
        return false;
    }

    copy_bytes(device->tx_buffer[slot], packet, length);
    if (length < RTL_MIN_FRAME) {
        zero_bytes(device->tx_buffer[slot] + length, RTL_MIN_FRAME - length);
        length = RTL_MIN_FRAME;
    }
    outl(status_port, length);
    device->tx_current = (uint8_t)((slot + 1) % RTL8139_NUM_TX_DESC);
    device->packets_transmitted++;
    return true;
}

// Each frame starts with a 4 byte status and length header, the length includes the CRC
bool rtl8139_receive_packet(network_interface_t* iface, void* buffer, uint32_t* length) {
    rtl8139_device_t* device = iface ? (rtl8139_device_t*)iface->driver_data : NULL;
    if (!device || !buffer || !length) return false;
    uint16_t io = device->io_base;
    if (inb(io + RTL8139_CR) & RTL8139_CR_BUFE) return false;

    uint8_t* header = device->rx_buffer + device->rx_current;
    uint16_t status = (uint16_t)(header[0] | (header[1] << 8));
    uint16_t frame = (uint16_t)(header[2] | (header[3] << 8));
    if (!(status & RTL_RX_ROK) || frame < RTL_CRC_SIZE + 14 || frame > RTL_MAX_FRAME + RTL_CRC_SIZE) {
        device->rx_errors++;
        restart_receiver(device);
        return false;
    }

    uint32_t data_length = frame - RTL_CRC_SIZE;
    bool fits = data_length <= *length;
    if (fits) copy_bytes(buffer, header + RTL_RX_HEADER, data_length);

    device->rx_current = (uint16_t)(((device->rx_current + frame + RTL_RX_HEADER + 3) & ~3u) % RTL8139_RX_BUFFER_SIZE);
    outw(io + RTL8139_CAPR, (uint16_t)(device->rx_current - RTL_CAPR_OFFSET));
    outw(io + RTL8139_ISR, RTL8139_INT_ROK | RTL8139_INT_RER | RTL8139_INT_RXOVW | RTL8139_INT_FOVW);

    if (!fits) {
        device->rx_errors++;
        return false;
    }
    device->packets_received++;
    *length = data_length;
    return true;
}

bool rtl8139_set_promiscuous(network_interface_t* iface, bool enable) {
    rtl8139_device_t* device = iface ? (rtl8139_device_t*)iface->driver_data : NULL;
    if (!device) return false;
    uint32_t rcr = inl(device->io_base + RTL8139_RCR);
    rcr = enable ? (rcr | RTL8139_RCR_AAP) : (rcr & ~(uint32_t)RTL8139_RCR_AAP);
    outl(device->io_base + RTL8139_RCR, rcr);
    return true;
}

bool rtl8139_get_link_status(network_interface_t* iface) {
    return iface && rtl8139_link_up((rtl8139_device_t*)iface->driver_data);
}

void rtl8139_dump_status(rtl8139_device_t* device) {
    if (!device) return;
    uint16_t io = device->io_base;
    terminal_write_string("RTL8139 I/O base ");
    terminal_write_hex(io);
    terminal_write_string("\n  CR ");
    terminal_write_hex(inb(io + RTL8139_CR));
    terminal_write_string("  ISR ");
    terminal_write_hex(inw(io + RTL8139_ISR));
    terminal_write_string("  RCR ");
    terminal_write_hex(inl(io + RTL8139_RCR));
    terminal_write_string("\n  CAPR ");
    terminal_write_uint(inw(io + RTL8139_CAPR));
    terminal_write_string("  CBR ");
    terminal_write_uint(inw(io + RTL8139_CBR));
    terminal_write_string("  read offset ");
    terminal_write_uint(device->rx_current);
    terminal_write_string("  link ");
    terminal_write_string(rtl8139_link_up(device) ? "up" : "down");
    terminal_write_string("\n  RX ");
    terminal_write_uint(device->packets_received);
    terminal_write_string("  TX ");
    terminal_write_uint(device->packets_transmitted);
    terminal_write_string("  RX errors ");
    terminal_write_uint(device->rx_errors);
    terminal_write_string("  TX errors ");
    terminal_write_uint(device->tx_errors);
    terminal_write_string("  missed ");
    terminal_write_uint(inl(io + RTL8139_MPC));
    terminal_write_string("\n");
}

static void register_interface(rtl8139_device_t* device) {
    char name[5] = {'e', 't', 'h', (char)('0' + network_interface_count()), '\0'};
    network_interface_t* iface = network_interface_register(name, rtl8139_send_packet, rtl8139_receive_packet, device);
    if (!iface) return;
    mac_address_t mac;
    rtl8139_get_mac_address(device, &mac);
    iface->set_promiscuous = rtl8139_set_promiscuous;
    iface->get_link_status = rtl8139_get_link_status;
    network_interface_set_mac_address(iface->interface_id, &mac);
    device->interface = iface;
}

bool rtl8139_probe_and_initialize_device(uint16_t bus, uint16_t device_num, uint16_t function) {
    if (device_count >= RTL_MAX_DEVICES || rtl8139_find_device(bus, device_num, function)) return false;
    uint32_t bar0 = pci_read_config_dword(bus, device_num, function, PCI_BAR0);
    if (!(bar0 & PCI_IO_BAR_FLAG)) return false;

    rtl8139_device_t* device = apollo_allocate_memory(sizeof(rtl8139_device_t));
    if (!device) return false;
    zero_bytes(device, sizeof(rtl8139_device_t));
    device->bus = bus;
    device->device = device_num;
    device->function = function;
    device->io_base = (uint16_t)(bar0 & ~0x03u);
    device->irq = pci_read_config_byte(bus, device_num, function, PCI_INTERRUPT_LINE);
    pci_write_config_word(bus, device_num, function, PCI_COMMAND,
                          pci_read_config_word(bus, device_num, function, PCI_COMMAND) | PCI_COMMAND_IO_AND_MASTER);

    rtl8139_reset(device);
    if (!allocate_buffers(device)) {
        free_buffers(device);
        apollo_free_memory(device);
        return false;
    }
    configure(device);
    register_interface(device);
    if (!device->interface) {
        free_buffers(device);
        apollo_free_memory(device);
        return false;
    }
    rtl8139_devices[device_count++] = device;
    return true;
}

rtl8139_device_t* rtl8139_find_device(uint16_t bus, uint16_t device, uint16_t function) {
    for (uint32_t i = 0; i < device_count; i++) {
        rtl8139_device_t* dev = rtl8139_devices[i];
        if (dev && dev->bus == bus && dev->device == device && dev->function == function) {
            return dev;
        }
    }
    return NULL;
}

bool rtl8139_driver_initialize(void) {
    if (device_count > 0) return true;
    return pci_scan_for_devices(RTL8139_VENDOR_ID, RTL8139_DEVICE_ID);
}
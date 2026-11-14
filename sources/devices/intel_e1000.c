#include "intel_e1000.h"
#include "network_interface.h"
#include "rtl8139_driver.h"
#include "heap_allocator.h"
#include "terminal.h"
#include "time_keeper.h"
#include "types.h"

#define E1000_MAX_DEVICES 4
#define PCI_COMMAND 0x04
#define PCI_COMMAND_MEMORY_IO_MASTER 0x07
#define PCI_BAR0 0x10
#define PCI_BAR_IO_FLAG 0x01
#define PCI_MAX_BUS 256
#define PCI_NO_DEVICE 0xFFFF
#define INTEL_VENDOR 0x8086
#define IO_ADDRESS_PORT 0
#define IO_DATA_PORT 4
#define RESET_WAIT_US 1000
#define RESET_POLLS 1000
#define DESCRIPTOR_ALIGN 128
#define MTA_ENTRIES 128
#define EERD_START 0x01
#define EERD_DONE 0x10
#define EERD_ADDRESS_SHIFT 8
#define EERD_DATA_SHIFT 16
#define EERD_POLLS 10000
#define TX_CMD_EOP 0x01
#define TX_CMD_IFCS 0x02
#define TX_CMD_RS 0x08
#define DESC_STATUS_DD 0x01
#define RX_STATUS_EOP 0x02
#define TCTL_CT_VALUE (0x10 << 4)
#define TCTL_COLD_VALUE (0x40 << 12)
#define TIPG_VALUE 0x0060200A   // IPGT 10, IPGR1 8, IPGR2 6 from the 8254x manual
#define MIN_FRAME 60

static const intel_device_id_t supported_devices[] = {
    {0x8086, 0x100E, "Intel 82540EM Gigabit Ethernet"},     // QEMU e1000
    {0x8086, 0x100F, "Intel 82545EM Gigabit Ethernet"},
    {0x8086, 0x10D3, "Intel 82574L Gigabit Ethernet"},      // QEMU e1000e
    {0x8086, 0x153A, "Intel I217-LM Gigabit Ethernet"},     // ThinkPad T440
    {0x8086, 0x153B, "Intel I217-V Gigabit Ethernet"},
    {0x8086, 0x15A0, "Intel I218-LM Gigabit Ethernet"},
    {0x8086, 0x15A1, "Intel I218-V Gigabit Ethernet"},
    {0x8086, 0x1502, "Intel 82579LM Gigabit Ethernet"},     // Common in ThinkPads
    {0x8086, 0x1503, "Intel 82579V Gigabit Ethernet"},
    {0x8086, 0x10EA, "Intel 82577LM Gigabit Ethernet"},
    {0x8086, 0x10EB, "Intel 82577LC Gigabit Ethernet"},
    {0x0000, 0x0000, NULL}
};

static intel_e1000_device_t* e1000_devices[E1000_MAX_DEVICES] = {NULL};
static uint32_t device_count = 0;

static inline void outl(uint16_t port, uint32_t data) {
    __asm__ volatile("outl %0, %1" : : "a"(data), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
    uint32_t result;
    __asm__ volatile("inl %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static uint32_t read_reg(intel_e1000_device_t* device, uint32_t reg) {
    if (device->use_io) {
        outl(device->io_base + IO_ADDRESS_PORT, reg);
        return inl(device->io_base + IO_DATA_PORT);
    }
    return *((volatile uint32_t*)(device->mem_base + reg));
}

static void write_reg(intel_e1000_device_t* device, uint32_t reg, uint32_t value) {
    if (device->use_io) {
        outl(device->io_base + IO_ADDRESS_PORT, reg);
        outl(device->io_base + IO_DATA_PORT, value);
        return;
    }
    *((volatile uint32_t*)(device->mem_base + reg)) = value;
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

static const intel_device_id_t* find_supported_device(uint16_t vendor_id, uint16_t device_id) {
    for (int i = 0; supported_devices[i].vendor_id != 0; i++) {
        if (supported_devices[i].vendor_id == vendor_id && supported_devices[i].device_id == device_id) {
            return &supported_devices[i];
        }
    }
    return NULL;
}

bool intel_e1000_supports(uint16_t vendor_id, uint16_t device_id) {
    return find_supported_device(vendor_id, device_id) != NULL;
}

intel_e1000_device_t* intel_e1000_find_device(uint16_t bus, uint16_t device, uint16_t function) {
    for (uint32_t i = 0; i < device_count; i++) {
        intel_e1000_device_t* dev = e1000_devices[i];
        if (dev && dev->bus == bus && dev->device == device && dev->function == function) return dev;
    }
    return NULL;
}

static void reset_device(intel_e1000_device_t* device) {
    write_reg(device, E1000_REG_IMC, 0xFFFFFFFF);
    write_reg(device, E1000_REG_CTRL, read_reg(device, E1000_REG_CTRL) | E1000_CTRL_RST);
    time_keeper_delay_us(RESET_WAIT_US);
    for (uint32_t i = 0; i < RESET_POLLS && (read_reg(device, E1000_REG_CTRL) & E1000_CTRL_RST); i++) {
        time_keeper_delay_us(RESET_WAIT_US);
    }
    write_reg(device, E1000_REG_IMC, 0xFFFFFFFF);
    read_reg(device, E1000_REG_ICR);
    write_reg(device, E1000_REG_CTRL, read_reg(device, E1000_REG_CTRL) | E1000_CTRL_SLU | E1000_CTRL_ASDE);
}

static bool eeprom_read(intel_e1000_device_t* device, uint8_t word, uint16_t* value) {
    write_reg(device, E1000_REG_EERD, EERD_START | ((uint32_t)word << EERD_ADDRESS_SHIFT));
    for (uint32_t i = 0; i < EERD_POLLS; i++) {
        uint32_t eerd = read_reg(device, E1000_REG_EERD);
        if (eerd & EERD_DONE) {
            *value = (uint16_t)(eerd >> EERD_DATA_SHIFT);
            return true;
        }
        time_keeper_delay_us(1);
    }
    return false;
}

// The receive address registers hold the MAC after reset on most parts, the EEPROM is the fallback
static bool read_mac_address(intel_e1000_device_t* device, mac_address_t* mac) {
    uint32_t ral = read_reg(device, E1000_REG_RAL);
    uint32_t rah = read_reg(device, E1000_REG_RAH);
    if (rah & E1000_RAH_AV) {
        for (int i = 0; i < 4; i++) mac->addr[i] = (uint8_t)(ral >> (8 * i));
        mac->addr[4] = (uint8_t)rah;
        mac->addr[5] = (uint8_t)(rah >> 8);
        return true;
    }
    for (uint8_t word = 0; word < 3; word++) {
        uint16_t value;
        if (!eeprom_read(device, word, &value)) return false;
        mac->addr[word * 2] = (uint8_t)value;
        mac->addr[word * 2 + 1] = (uint8_t)(value >> 8);
    }
    write_reg(device, E1000_REG_RAL, mac->addr[0] | (mac->addr[1] << 8) | (mac->addr[2] << 16) | ((uint32_t)mac->addr[3] << 24));
    write_reg(device, E1000_REG_RAH, mac->addr[4] | (mac->addr[5] << 8) | E1000_RAH_AV);
    return true;
}

static void* alloc_aligned(uint32_t size) {
    uint8_t* raw = apollo_allocate_memory(size + DESCRIPTOR_ALIGN);
    if (!raw) return NULL;
    uint8_t* aligned = (uint8_t*)(((uintptr_t)raw + DESCRIPTOR_ALIGN - 1) & ~(uintptr_t)(DESCRIPTOR_ALIGN - 1));
    zero_bytes(aligned, size);
    return aligned;
}

static bool setup_rings(intel_e1000_device_t* device) {
    device->rx_ring = alloc_aligned(sizeof(e1000_rx_descriptor_t) * E1000_RX_DESCRIPTORS);
    device->tx_ring = alloc_aligned(sizeof(e1000_tx_descriptor_t) * E1000_TX_DESCRIPTORS);
    if (!device->rx_ring || !device->tx_ring) return false;
    for (uint32_t i = 0; i < E1000_RX_DESCRIPTORS; i++) {
        device->rx_buffers[i] = apollo_allocate_memory(E1000_BUFFER_SIZE);
        if (!device->rx_buffers[i]) return false;
        device->rx_ring[i].address = (uintptr_t)device->rx_buffers[i];
    }
    for (uint32_t i = 0; i < E1000_TX_DESCRIPTORS; i++) {
        device->tx_buffers[i] = apollo_allocate_memory(E1000_BUFFER_SIZE);
        if (!device->tx_buffers[i]) return false;
        device->tx_ring[i].address = (uintptr_t)device->tx_buffers[i];
        device->tx_ring[i].status = DESC_STATUS_DD;
    }
    return true;
}

static void start_dma(intel_e1000_device_t* device) {
    for (uint32_t i = 0; i < MTA_ENTRIES; i++) write_reg(device, E1000_REG_MTA + i * 4, 0);
    uint64_t rx = (uintptr_t)device->rx_ring;
    write_reg(device, E1000_REG_RDBAL, (uint32_t)rx);
    write_reg(device, E1000_REG_RDBAH, (uint32_t)(rx >> 32));
    write_reg(device, E1000_REG_RDLEN, sizeof(e1000_rx_descriptor_t) * E1000_RX_DESCRIPTORS);
    write_reg(device, E1000_REG_RDH, 0);
    write_reg(device, E1000_REG_RDT, E1000_RX_DESCRIPTORS - 1);
    write_reg(device, E1000_REG_RCTL, E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SECRC | E1000_RCTL_SZ_2048);

    uint64_t tx = (uintptr_t)device->tx_ring;
    write_reg(device, E1000_REG_TDBAL, (uint32_t)tx);
    write_reg(device, E1000_REG_TDBAH, (uint32_t)(tx >> 32));
    write_reg(device, E1000_REG_TDLEN, sizeof(e1000_tx_descriptor_t) * E1000_TX_DESCRIPTORS);
    write_reg(device, E1000_REG_TDH, 0);
    write_reg(device, E1000_REG_TDT, 0);
    write_reg(device, E1000_REG_TIPG, TIPG_VALUE);
    write_reg(device, E1000_REG_TCTL, E1000_TCTL_EN | E1000_TCTL_PSP | TCTL_CT_VALUE | TCTL_COLD_VALUE);
    device->rx_next = 0;
    device->tx_next = 0;
}

/* data path */

static bool e1000_send_packet(network_interface_t* iface, const void* packet, uint32_t length) {
    intel_e1000_device_t* device = iface ? (intel_e1000_device_t*)iface->driver_data : NULL;
    if (!device || !packet || length == 0 || length > E1000_BUFFER_SIZE) return false;
    e1000_tx_descriptor_t* desc = &device->tx_ring[device->tx_next];
    if (!(desc->status & DESC_STATUS_DD)) {
        device->tx_errors++;
        return false;
    }
    copy_bytes(device->tx_buffers[device->tx_next], packet, length);
    if (length < MIN_FRAME) {
        zero_bytes(device->tx_buffers[device->tx_next] + length, MIN_FRAME - length);
        length = MIN_FRAME;
    }
    desc->length = (uint16_t)length;
    desc->command = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
    desc->status = 0;
    device->tx_next = (device->tx_next + 1) % E1000_TX_DESCRIPTORS;
    write_reg(device, E1000_REG_TDT, device->tx_next);
    device->packets_transmitted++;
    return true;
}

// Frames that span descriptors cannot happen with 2KB buffers and a 1518 byte limit, they are dropped
static bool e1000_receive_packet(network_interface_t* iface, void* buffer, uint32_t* length) {
    intel_e1000_device_t* device = iface ? (intel_e1000_device_t*)iface->driver_data : NULL;
    if (!device || !buffer || !length) return false;
    e1000_rx_descriptor_t* desc = &device->rx_ring[device->rx_next];
    if (!(desc->status & DESC_STATUS_DD)) return false;
    bool ok = (desc->status & RX_STATUS_EOP) && desc->errors == 0 && desc->length <= *length;
    if (ok) {
        copy_bytes(buffer, device->rx_buffers[device->rx_next], desc->length);
        *length = desc->length;
        device->packets_received++;
    } else {
        device->rx_errors++;
    }
    desc->status = 0;
    write_reg(device, E1000_REG_RDT, device->rx_next);
    device->rx_next = (device->rx_next + 1) % E1000_RX_DESCRIPTORS;
    return ok;
}

static bool e1000_set_promiscuous(network_interface_t* iface, bool enable) {
    intel_e1000_device_t* device = iface ? (intel_e1000_device_t*)iface->driver_data : NULL;
    if (!device) return false;
    uint32_t rctl = read_reg(device, E1000_REG_RCTL);
    rctl = enable ? (rctl | E1000_RCTL_UPE | E1000_RCTL_MPE) : (rctl & ~(uint32_t)(E1000_RCTL_UPE | E1000_RCTL_MPE));
    write_reg(device, E1000_REG_RCTL, rctl);
    return true;
}

static bool e1000_get_link_status(network_interface_t* iface) {
    intel_e1000_device_t* device = iface ? (intel_e1000_device_t*)iface->driver_data : NULL;
    return device && (read_reg(device, E1000_REG_STATUS) & E1000_STATUS_LU);
}

void intel_e1000_dump_device_info(intel_e1000_device_t* device) {
    if (!device) return;
    terminal_write_string("E1000 ");
    terminal_write_hex(device->vendor_id);
    terminal_write_string(":");
    terminal_write_hex(device->device_id);
    terminal_write_string(device->use_io ? " I/O " : " MMIO ");
    terminal_write_hex(device->use_io ? device->io_base : device->mem_base);
    terminal_write_string("\n  link ");
    terminal_write_string(read_reg(device, E1000_REG_STATUS) & E1000_STATUS_LU ? "up" : "down");
    terminal_write_string("  RDH ");
    terminal_write_uint(read_reg(device, E1000_REG_RDH));
    terminal_write_string("  RDT ");
    terminal_write_uint(read_reg(device, E1000_REG_RDT));
    terminal_write_string("  TDH ");
    terminal_write_uint(read_reg(device, E1000_REG_TDH));
    terminal_write_string("  TDT ");
    terminal_write_uint(read_reg(device, E1000_REG_TDT));
    terminal_write_string("\n  RX ");
    terminal_write_uint(device->packets_received);
    terminal_write_string("  TX ");
    terminal_write_uint(device->packets_transmitted);
    terminal_write_string("  RX errors ");
    terminal_write_uint(device->rx_errors);
    terminal_write_string("  TX errors ");
    terminal_write_uint(device->tx_errors);
    terminal_write_string("\n");
}

static bool map_registers(intel_e1000_device_t* dev, uint16_t bus, uint16_t device_num, uint16_t function) {
    uint32_t bar0 = pci_read_config_dword(bus, device_num, function, PCI_BAR0);
    dev->use_io = (bar0 & PCI_BAR_IO_FLAG) != 0;
    if (dev->use_io) dev->io_base = (uint16_t)(bar0 & ~0x3u);
    else dev->mem_base = bar0 & ~0xFu;  // Covered by the 4GB identity map from boot
    return dev->use_io ? dev->io_base != 0 : dev->mem_base != 0;
}

static bool register_interface(intel_e1000_device_t* dev) {
    mac_address_t mac;
    if (!read_mac_address(dev, &mac)) return false;
    char name[5] = {'e', 't', 'h', (char)('0' + network_interface_count()), '\0'};
    network_interface_t* iface = network_interface_register(name, e1000_send_packet, e1000_receive_packet, dev);
    if (!iface) return false;
    iface->set_promiscuous = e1000_set_promiscuous;
    iface->get_link_status = e1000_get_link_status;
    network_interface_set_mac_address(iface->interface_id, &mac);
    dev->interface = iface;
    return true;
}

bool intel_e1000_probe_and_initialize_device(uint16_t bus, uint16_t device_num, uint16_t function) {
    if (device_count >= E1000_MAX_DEVICES || intel_e1000_find_device(bus, device_num, function)) return false;
    uint32_t id = pci_read_config_dword(bus, device_num, function, 0x00);
    if (!find_supported_device((uint16_t)id, (uint16_t)(id >> 16))) return false;

    intel_e1000_device_t* dev = apollo_allocate_memory(sizeof(intel_e1000_device_t));
    if (!dev) return false;
    zero_bytes(dev, sizeof(intel_e1000_device_t));
    dev->bus = bus;
    dev->device = device_num;
    dev->function = function;
    dev->vendor_id = (uint16_t)id;
    dev->device_id = (uint16_t)(id >> 16);
    pci_write_config_word(bus, device_num, function, PCI_COMMAND,
                          pci_read_config_word(bus, device_num, function, PCI_COMMAND) | PCI_COMMAND_MEMORY_IO_MASTER);
    if (!map_registers(dev, bus, device_num, function)) {
        apollo_free_memory(dev);
        return false;
    }
    reset_device(dev);
    if (!setup_rings(dev) || !register_interface(dev)) {
        terminal_write_string("E1000: initialization failed, rings or MAC address unavailable\n");
        return false;
    }
    start_dma(dev);
    e1000_devices[device_count++] = dev;
    return true;
}

bool intel_e1000_driver_initialize(void) {
    if (device_count > 0) return true;
    bool found = false;
    for (uint16_t bus = 0; bus < PCI_MAX_BUS; bus++) {
        for (uint16_t device = 0; device < 32; device++) {
            for (uint16_t function = 0; function < 8; function++) {
                uint16_t vendor = pci_read_config_word(bus, device, function, 0x00);
                if (vendor == PCI_NO_DEVICE) {
                    if (function == 0) break;
                    continue;
                }
                if (vendor == INTEL_VENDOR) found |= intel_e1000_probe_and_initialize_device(bus, device, function);
            }
        }
    }
    return found;
}
#include "pci_scan.h"
#include "terminal.h"

typedef struct {
    uint16_t vendor_id;
    uint16_t device_id;
    const char* vendor_name;
    const char* device_name;
    const char* class_name;
} pci_device_info_t;

static const pci_device_info_t network_controllers[] = {
    {0x10EC, 0x8139, "Realtek", "RTL8139 Fast Ethernet", "Network"},
    
    {0x8086, 0x153A, "Intel", "I217-LM Gigabit Ethernet", "Network"},
    {0x8086, 0x153B, "Intel", "I217-V Gigabit Ethernet", "Network"},
    {0x8086, 0x15A0, "Intel", "I218-LM Gigabit Ethernet", "Network"},
    {0x8086, 0x15A1, "Intel", "I218-V Gigabit Ethernet", "Network"},
    {0x8086, 0x15A2, "Intel", "I218-LM Gigabit Ethernet", "Network"},
    {0x8086, 0x15A3, "Intel", "I218-V Gigabit Ethernet", "Network"},
    {0x8086, 0x1502, "Intel", "82579LM Gigabit Ethernet", "Network"},
    {0x8086, 0x1503, "Intel", "82579V Gigabit Ethernet", "Network"},
    {0x8086, 0x10EA, "Intel", "82577LM Gigabit Ethernet", "Network"},
    {0x8086, 0x10EB, "Intel", "82577LC Gigabit Ethernet", "Network"},
    
    {0x10EC, 0x8168, "Realtek", "RTL8168 Gigabit Ethernet", "Network"},
    {0x10EC, 0x8111, "Realtek", "RTL8111 Gigabit Ethernet", "Network"},
    {0x10EC, 0x8167, "Realtek", "RTL8167 Gigabit Ethernet", "Network"},
    
    {0x14E4, 0x1684, "Broadcom", "NetXtreme BCM5764M", "Network"},
    {0x14E4, 0x1686, "Broadcom", "NetXtreme BCM57766", "Network"},
    
    {0x0000, 0x0000, NULL, NULL, NULL} // Terminator
};

static uint32_t pci_read_config_dword(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    uint32_t address = 0x80000000 | ((uint32_t)bus << 16) | 
                      ((uint32_t)device << 11) | ((uint32_t)function << 8) | 
                      (offset & 0xFC);
    
    outl(0xCF8, address);
    return inl(0xCFC);
}

static uint16_t pci_read_config_word(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    uint32_t dword = pci_read_config_dword(bus, device, function, offset & 0xFC);
    return (uint16_t)(dword >> ((offset & 2) * 8));
}

static uint8_t pci_read_config_byte(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    uint32_t dword = pci_read_config_dword(bus, device, function, offset & 0xFC);
    return (uint8_t)(dword >> ((offset & 3) * 8));
}

static const pci_device_info_t* find_device_info(uint16_t vendor_id, uint16_t device_id) {
    for (int i = 0; network_controllers[i].vendor_id != 0; i++) {
        if (network_controllers[i].vendor_id == vendor_id && 
            network_controllers[i].device_id == device_id) {
            return &network_controllers[i];
        }
    }
    return NULL;
}

#define PCI_MAX_BUS 8
#define PCI_MAX_DEVICE 32
#define PCI_MAX_FUNCTION 8
#define PCI_NO_DEVICE 0xFFFF

uint32_t pci_enumerate(pci_device_t* devices, uint32_t max_devices) {
    uint32_t count = 0;
    for (uint16_t bus = 0; bus < PCI_MAX_BUS; bus++) {
        for (uint16_t device = 0; device < PCI_MAX_DEVICE; device++) {
            for (uint16_t function = 0; function < PCI_MAX_FUNCTION; function++) {
                uint16_t vendor = pci_read_config_word(bus, device, function, 0x00);
                if (vendor == PCI_NO_DEVICE) {
                    if (function == 0) break;
                    continue;
                }
                if (count >= max_devices) return count;
                devices[count].bus = bus;
                devices[count].device = device;
                devices[count].function = function;
                devices[count].vendor_id = vendor;
                devices[count].device_id = pci_read_config_word(bus, device, function, 0x02);
                devices[count].class_code = pci_read_config_byte(bus, device, function, 0x0B);
                devices[count].subclass = pci_read_config_byte(bus, device, function, 0x0A);
                count++;
            }
        }
    }
    return count;
}

const char* pci_device_name(uint16_t vendor_id, uint16_t device_id) {
    const pci_device_info_t* info = find_device_info(vendor_id, device_id);
    return info ? info->device_name : NULL;
}

void pci_scan_all_devices(void) {
    terminal_write_string("PCI Device Scan Results:\n");
    terminal_write_string("========================\n");
    terminal_write_string("Bus Dev Fn VendID DevID Class    Description\n");
    terminal_write_string("--- --- -- ------ ------ -------- -----------\n");
    
    uint32_t devices_found = 0;
    uint32_t network_devices = 0;
    
    for (uint16_t bus = 0; bus < 8; bus++) {        // Limit bus scan for speed
        for (uint16_t device = 0; device < 32; device++) {
            for (uint16_t function = 0; function < 8; function++) {
                uint16_t vendor = pci_read_config_word(bus, device, function, 0x00);
                
                if (vendor == 0xFFFF) {
                    if (function == 0) break; // No device
                    continue; // Try next function
                }
                
                uint16_t device_id = pci_read_config_word(bus, device, function, 0x02);
                uint8_t class_code = pci_read_config_byte(bus, device, function, 0x0B);
                uint8_t subclass = pci_read_config_byte(bus, device, function, 0x0A);
                
                devices_found++;
                
                if (bus < 10) terminal_write_string(" ");
                terminal_write_uint(bus);
                terminal_write_string("   ");
                
                if (device < 10) terminal_write_string(" ");
                terminal_write_uint(device);
                terminal_write_string("  ");
                
                terminal_write_uint(function);
                terminal_write_string("  ");
                
                terminal_write_hex(vendor);
                terminal_write_string(" ");
                terminal_write_hex(device_id);
                terminal_write_string(" ");
                
                if (class_code == 0x02) {
                    terminal_write_string("Network ");
                    network_devices++;
                } else if (class_code == 0x01) {
                    terminal_write_string("Storage ");
                } else if (class_code == 0x03) {
                    terminal_write_string("Display ");
                } else if (class_code == 0x06) {
                    terminal_write_string("Bridge  ");
                } else if (class_code == 0x0C) {
                    terminal_write_string("SerialBus");
                } else {
                    terminal_write_hex(class_code);
                    terminal_write_string(".");
                    terminal_write_hex(subclass);
                    terminal_write_string("   ");
                }
                terminal_write_string(" ");
                
                const pci_device_info_t* info = find_device_info(vendor, device_id);
                if (info) {
                    terminal_write_string(info->vendor_name);
                    terminal_write_string(" ");
                    terminal_write_string(info->device_name);
                } else {
                    if (vendor == 0x8086) {
                        terminal_write_string("Intel (Unknown device)");
                    } else if (vendor == 0x10EC) {
                        terminal_write_string("Realtek (Unknown device)");
                    } else if (vendor == 0x14E4) {
                        terminal_write_string("Broadcom (Unknown device)");
                    } else if (vendor == 0x1022) {
                        terminal_write_string("AMD (Unknown device)");
                    } else {
                        terminal_write_string("Unknown device");
                    }
                }
                terminal_write_string("\n");
            }
        }
    }
    
    terminal_write_string("\nSummary:\n");
    terminal_write_string("  Total devices found: ");
    terminal_write_uint(devices_found);
    terminal_write_string("\n");
    terminal_write_string("  Network devices: ");
    terminal_write_uint(network_devices);
    terminal_write_string("\n");
    
    if (network_devices == 0) {
        terminal_set_color(12, 0); // Red
        terminal_write_string("\n  WARNING: No network devices found\n");
        terminal_set_color(7, 0);
    }
}

bool pci_find_network_devices(pci_network_device_t* devices, uint32_t max_devices, uint32_t* found_count) {
    *found_count = 0;
    
    for (uint16_t bus = 0; bus < 8 && *found_count < max_devices; bus++) {
        for (uint16_t device = 0; device < 32 && *found_count < max_devices; device++) {
            for (uint16_t function = 0; function < 8 && *found_count < max_devices; function++) {
                uint16_t vendor = pci_read_config_word(bus, device, function, 0x00);
                
                if (vendor == 0xFFFF) {
                    if (function == 0) break;
                    continue;
                }
                
                uint16_t device_id = pci_read_config_word(bus, device, function, 0x02);
                uint8_t class_code = pci_read_config_byte(bus, device, function, 0x0B);
                
                if (class_code == 0x02) {
                    devices[*found_count].bus = bus;
                    devices[*found_count].device = device;
                    devices[*found_count].function = function;
                    devices[*found_count].vendor_id = vendor;
                    devices[*found_count].device_id = device_id;
                    
                    const pci_device_info_t* info = find_device_info(vendor, device_id);
                    if (info) {
                        int i = 0;
                        while (info->vendor_name[i] && i < 31) {
                            devices[*found_count].vendor_name[i] = info->vendor_name[i];
                            i++;
                        }
                        devices[*found_count].vendor_name[i] = '\0';
                        
                        i = 0;
                        while (info->device_name[i] && i < 63) {
                            devices[*found_count].device_name[i] = info->device_name[i];
                            i++;
                        }
                        devices[*found_count].device_name[i] = '\0';
                    } else {
                        if (vendor == 0x8086) {
                            const char* name = "Intel";
                            for (int i = 0; i < 5; i++) devices[*found_count].vendor_name[i] = name[i];
                            devices[*found_count].vendor_name[5] = '\0';
                        } else {
                            const char* name = "Unknown";
                            for (int i = 0; i < 7; i++) devices[*found_count].vendor_name[i] = name[i];
                            devices[*found_count].vendor_name[7] = '\0';
                        }
                        
                        const char* dev_name = "Unknown Network Device";
                        for (int i = 0; i < 22; i++) devices[*found_count].device_name[i] = dev_name[i];
                        devices[*found_count].device_name[22] = '\0';
                    }
                    
                    (*found_count)++;
                }
            }
        }
    }
    
    return *found_count > 0;
}
#ifndef APOLLO_PCI_SCAN_H
#define APOLLO_PCI_SCAN_H

#include "types.h"

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA 0xCFC

#define PCI_CLASS_NETWORK 0x02
#define PCI_CLASS_STORAGE 0x01
#define PCI_CLASS_DISPLAY 0x03
#define PCI_CLASS_BRIDGE 0x06

typedef struct {
    uint16_t bus;
    uint16_t device;
    uint16_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    char vendor_name[32];
    char device_name[64];
} pci_network_device_t;

typedef struct {
    uint16_t bus;
    uint16_t device;
    uint16_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_code;
    uint8_t subclass;
} pci_device_t;

void pci_scan_all_devices(void);
uint32_t pci_enumerate(pci_device_t* devices, uint32_t max_devices);
const char* pci_device_name(uint16_t vendor_id, uint16_t device_id);
bool pci_find_network_devices(pci_network_device_t* devices, uint32_t max_devices, uint32_t* found_count);

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

#endif
#ifndef APOLLO_SAFE_HARDWARE_H
#define APOLLO_SAFE_HARDWARE_H

#include "types.h"

#define HARDWARE_FAULT_NONE       0
#define HARDWARE_FAULT_PCI        1
#define HARDWARE_FAULT_MMIO       2
#define HARDWARE_FAULT_IO_PORT    3
#define HARDWARE_FAULT_TIMEOUT    4

void hardware_fault_handler(uint32_t fault_address, uint32_t error_code);

uint32_t safe_pci_read_dword(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset);
uint16_t safe_pci_read_word(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset);
uint8_t safe_pci_read_byte(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset);
bool safe_pci_write_dword(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint32_t value);
bool safe_pci_write_word(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint16_t value);
bool safe_pci_write_byte(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint8_t value);

uint32_t safe_inl(uint16_t port);
uint16_t safe_inw(uint16_t port);
uint8_t safe_inb(uint16_t port);
bool safe_outl(uint16_t port, uint32_t value);
bool safe_outw(uint16_t port, uint16_t value);
bool safe_outb(uint16_t port, uint8_t value);

uint32_t safe_mmio_read32(volatile uint32_t* address);
uint16_t safe_mmio_read16(volatile uint16_t* address);
uint8_t safe_mmio_read8(volatile uint8_t* address);
bool safe_mmio_write32(volatile uint32_t* address, uint32_t value);
bool safe_mmio_write16(volatile uint16_t* address, uint16_t value);
bool safe_mmio_write8(volatile uint8_t* address, uint8_t value);

bool hardware_access_test(void);
bool validate_hardware_address(void* address);
bool is_hardware_accessible(void);
uint32_t get_last_hardware_fault(void);
void reset_hardware_fault_status(void);

#ifdef ENABLE_HARDWARE_SAFETY
    #ifndef inl
    #define inl(port) safe_inl(port)
    #endif
    
    #ifndef inw
    #define inw(port) safe_inw(port)
    #endif
    
    #ifndef inb
    #define inb(port) safe_inb(port)
    #endif
    
    #ifndef outl
    #define outl(port, val) safe_outl(port, val)
    #endif
    
    #ifndef outw
    #define outw(port, val) safe_outw(port, val)
    #endif
    
    #ifndef outb
    #define outb(port, val) safe_outb(port, val)
    #endif
    
    #ifndef pci_read_config_dword
    #define pci_read_config_dword(bus, dev, func, offset) safe_pci_read_dword(bus, dev, func, offset)
    #endif
    
    #ifndef pci_read_config_word
    #define pci_read_config_word(bus, dev, func, offset) safe_pci_read_word(bus, dev, func, offset)
    #endif
    
    #ifndef pci_read_config_byte
    #define pci_read_config_byte(bus, dev, func, offset) safe_pci_read_byte(bus, dev, func, offset)
    #endif
    
    #ifndef pci_write_config_dword
    #define pci_write_config_dword(bus, dev, func, offset, val) safe_pci_write_dword(bus, dev, func, offset, val)
    #endif
    
    #ifndef pci_write_config_word
    #define pci_write_config_word(bus, dev, func, offset, val) safe_pci_write_word(bus, dev, func, offset, val)
    #endif
    
    #ifndef pci_write_config_byte
    #define pci_write_config_byte(bus, dev, func, offset, val) safe_pci_write_byte(bus, dev, func, offset, val)
    #endif
#endif

#endif
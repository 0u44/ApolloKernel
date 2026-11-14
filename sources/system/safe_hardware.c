#include "safe_hardware.h"
#include "time_keeper.h"
#include "terminal.h"
#include "types.h"

static volatile bool hardware_exception_occurred = false;
static volatile uint32_t last_fault_address = 0;
static volatile uint32_t last_fault_code = 0;
static volatile uint32_t fault_count = 0;

extern uint8_t __kernel_start[];
extern uint8_t __kernel_end[];

#define HARDWARE_TIMEOUT_TICKS 1000

static inline void io_delay(void) {
    __asm__ volatile ("nop; nop; nop; nop;");
}

void hardware_fault_handler(uint32_t fault_address, uint32_t error_code) {
    hardware_exception_occurred = true;
    last_fault_address = fault_address;
    last_fault_code = error_code;
    fault_count++;

    terminal_set_color(12, 0);
    terminal_write_string("HARDWARE FAULT RECOVERED: Addr=");
    terminal_write_hex(fault_address);
    terminal_write_string(" Err=");
    terminal_write_hex(error_code);
    terminal_write_string("\n");
    terminal_set_color(7, 0);
}

void reset_hardware_fault_status(void) {
    hardware_exception_occurred = false;
    last_fault_address = 0;
    last_fault_code = 0;
}

uint32_t get_last_hardware_fault(void) {
    return last_fault_code;
}

uint32_t safe_pci_read_dword(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    reset_hardware_fault_status();

    uint32_t address = 0x80000000 |
                      ((uint32_t)bus << 16) |
                      ((uint32_t)device << 11) |
                      ((uint32_t)function << 8) |
                      (offset & 0xFC);

    uint32_t result = 0;
    uint32_t start_time = (uint32_t)time_keeper_get_uptime_seconds();

    __asm__ volatile (
        "movl %1, %%eax\n\t"
        "movl $0xCF8, %%edx\n\t"
        "outl %%eax, %%dx\n\t"
        "movl $0xCFC, %%edx\n\t"
        "inl %%dx, %%eax\n\t"
        "movl %%eax, %0"
        : "=m" (result)
        : "m" (address)
        : "eax", "edx"
    );

    io_delay();

    uint32_t elapsed = get_system_time() - start_time;
    if (hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS) {
        if (elapsed > HARDWARE_TIMEOUT_TICKS) {
            terminal_set_color(14, 0);
            terminal_write_string("WARNING: PCI read timeout\n");
            terminal_set_color(7, 0);
        }
        return 0xFFFFFFFF;  // Return invalid value
    }

    return result;
}

uint16_t safe_pci_read_word(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    uint32_t dword = safe_pci_read_dword(bus, device, function, offset & 0xFC);
    if (dword == 0xFFFFFFFF) {
        return 0xFFFF;
    }

    if (offset & 0x02) {
        return (uint16_t)(dword >> 16);
    } else {
        return (uint16_t)(dword & 0xFFFF);
    }
}

uint8_t safe_pci_read_byte(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset) {
    uint32_t dword = safe_pci_read_dword(bus, device, function, offset & 0xFC);
    if (dword == 0xFFFFFFFF) {
        return 0xFF;
    }

    uint8_t byte_offset = offset & 0x03;
    return (uint8_t)(dword >> (byte_offset * 8));
}

bool safe_pci_write_dword(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint32_t value) {
    reset_hardware_fault_status();

    uint32_t address = 0x80000000 |
                      ((uint32_t)bus << 16) |
                      ((uint32_t)device << 11) |
                      ((uint32_t)function << 8) |
                      (offset & 0xFC);

    uint32_t start_time = get_system_time();

    __asm__ volatile (
        "movl %0, %%eax\n\t"
        "movl $0xCF8, %%edx\n\t"
        "outl %%eax, %%dx\n\t"
        "movl %1, %%eax\n\t"
        "movl $0xCFC, %%edx\n\t"
        "outl %%eax, %%dx"
        :
        : "m" (address), "m" (value)
        : "eax", "edx"
    );

    io_delay();

    uint32_t elapsed = get_system_time() - start_time;
    return !hardware_exception_occurred && (elapsed <= HARDWARE_TIMEOUT_TICKS);
}

bool safe_pci_write_word(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint16_t value) {
    uint32_t current = safe_pci_read_dword(bus, device, function, offset & 0xFC);
    if (current == 0xFFFFFFFF) {
        return false;
    }

    uint32_t new_value;
    if (offset & 0x02) {
        new_value = (current & 0x0000FFFF) | ((uint32_t)value << 16);
    } else {
        new_value = (current & 0xFFFF0000) | value;
    }

    return safe_pci_write_dword(bus, device, function, offset & 0xFC, new_value);
}

bool safe_pci_write_byte(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint8_t value) {
    uint32_t current = safe_pci_read_dword(bus, device, function, offset & 0xFC);
    if (current == 0xFFFFFFFF) {
        return false;
    }

    uint8_t byte_offset = offset & 0x03;
    uint32_t mask = 0xFF << (byte_offset * 8);
    uint32_t new_value = (current & ~mask) | ((uint32_t)value << (byte_offset * 8));

    return safe_pci_write_dword(bus, device, function, offset & 0xFC, new_value);
}

uint32_t safe_inl(uint16_t port) {
    reset_hardware_fault_status();

    uint32_t result = 0;
    uint32_t start_time = get_system_time();

    __asm__ volatile (
        "inl %1, %0"
        : "=a" (result)
        : "d" (port)
    );

    io_delay();

    uint32_t elapsed = get_system_time() - start_time;
    if (hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS) {
        return 0xFFFFFFFF;
    }

    return result;
}

uint16_t safe_inw(uint16_t port) {
    reset_hardware_fault_status();

    uint16_t result = 0;
    uint32_t start_time = get_system_time();

    __asm__ volatile (
        "inw %1, %0"
        : "=a" (result)
        : "d" (port)
    );

    io_delay();

    uint32_t elapsed = get_system_time() - start_time;
    if (hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS) {
        return 0xFFFF;
    }

    return result;
}

uint8_t safe_inb(uint16_t port) {
    reset_hardware_fault_status();

    uint8_t result = 0;
    uint32_t start_time = get_system_time();

    __asm__ volatile (
        "inb %1, %0"
        : "=a" (result)
        : "d" (port)
    );

    io_delay();

    uint32_t elapsed = get_system_time() - start_time;
    if (hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS) {
        return 0xFF;
    }

    return result;
}

bool safe_outl(uint16_t port, uint32_t value) {
    reset_hardware_fault_status();

    uint32_t start_time = get_system_time();

    __asm__ volatile (
        "outl %0, %1"
        :
        : "a" (value), "d" (port)
    );

    io_delay();

    uint32_t elapsed = get_system_time() - start_time;
    return !hardware_exception_occurred && (elapsed <= HARDWARE_TIMEOUT_TICKS);
}

bool safe_outw(uint16_t port, uint16_t value) {
    reset_hardware_fault_status();

    uint32_t start_time = get_system_time();

    __asm__ volatile (
        "outw %0, %1"
        :
        : "a" (value), "d" (port)
    );

    io_delay();

    uint32_t elapsed = get_system_time() - start_time;
    return !hardware_exception_occurred && (elapsed <= HARDWARE_TIMEOUT_TICKS);
}

bool safe_outb(uint16_t port, uint8_t value) {
    reset_hardware_fault_status();

    uint32_t start_time = get_system_time();

    __asm__ volatile (
        "outb %0, %1"
        :
        : "a" (value), "d" (port)
    );

    io_delay();

    uint32_t elapsed = get_system_time() - start_time;
    return !hardware_exception_occurred && (elapsed <= HARDWARE_TIMEOUT_TICKS);
}

uint32_t safe_mmio_read32(volatile uint32_t* address) {
    uintptr_t addr = (uintptr_t)address;
    if (addr < 0x1000 || addr > 0xFFFFF000) {
        terminal_set_color(12, 0);
        terminal_write_string("ERROR: Invalid MMIO address rejected: ");
        terminal_write_hex(addr);
        terminal_write_string("\n");
        terminal_set_color(7, 0);
        return 0xFFFFFFFF;
    }

    reset_hardware_fault_status();

    uint32_t start_time = get_system_time();
    uint32_t result = *address;
    uint32_t elapsed = get_system_time() - start_time;

    if (hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS) {
        terminal_set_color(14, 0);
        terminal_write_string("WARNING: MMIO read fault detected at ");
        terminal_write_hex(addr);
        terminal_write_string("\n");
        terminal_set_color(7, 0);
        return 0xFFFFFFFF;
    }

    return result;
}

uint16_t safe_mmio_read16(volatile uint16_t* address) {
    uintptr_t addr = (uintptr_t)address;
    if (addr < 0x1000 || addr > 0xFFFFF000) {
        return 0xFFFF;
    }

    reset_hardware_fault_status();

    uint32_t start_time = get_system_time();
    uint16_t result = *address;
    uint32_t elapsed = get_system_time() - start_time;

    return (hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS) ? 0xFFFF : result;
}

uint8_t safe_mmio_read8(volatile uint8_t* address) {
    uintptr_t addr = (uintptr_t)address;
    if (addr < 0x1000 || addr > 0xFFFFF000) {
        return 0xFF;
    }

    reset_hardware_fault_status();

    uint32_t start_time = get_system_time();
    uint8_t result = *address;
    uint32_t elapsed = get_system_time() - start_time;

    return (hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS) ? 0xFF : result;
}

bool safe_mmio_write32(volatile uint32_t* address, uint32_t value) {
    uintptr_t addr = (uintptr_t)address;
    if (addr < 0x1000 || addr > 0xFFFFF000) {
        terminal_set_color(12, 0);
        terminal_write_string("ERROR: Invalid MMIO write address rejected: ");
        terminal_write_hex(addr);
        terminal_write_string("\n");
        terminal_set_color(7, 0);
        return false;
    }

    reset_hardware_fault_status();

    uint32_t start_time = get_system_time();
    *address = value;
    uint32_t elapsed = get_system_time() - start_time;

    if (hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS) {
        terminal_set_color(14, 0);
        terminal_write_string("WARNING: MMIO write fault detected at ");
        terminal_write_hex(addr);
        terminal_write_string("\n");
        terminal_set_color(7, 0);
        return false;
    }

    return true;
}

bool safe_mmio_write16(volatile uint16_t* address, uint16_t value) {
    uintptr_t addr = (uintptr_t)address;
    if (addr < 0x1000 || addr > 0xFFFFF000) {
        return false;
    }

    reset_hardware_fault_status();

    uint32_t start_time = get_system_time();
    *address = value;
    uint32_t elapsed = get_system_time() - start_time;

    return !(hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS);
}

bool safe_mmio_write8(volatile uint8_t* address, uint8_t value) {
    uintptr_t addr = (uintptr_t)address;
    if (addr < 0x1000 || addr > 0xFFFFF000) {
        return false;
    }

    reset_hardware_fault_status();

    uint32_t start_time = get_system_time();
    *address = value;
    uint32_t elapsed = get_system_time() - start_time;

    return !(hardware_exception_occurred || elapsed > HARDWARE_TIMEOUT_TICKS);
}

bool hardware_access_test(void) {
    terminal_write_string("Testing safe hardware access...\n");

    reset_hardware_fault_status();

    uint32_t test_result = safe_pci_read_dword(0, 0, 0, 0);
    if (test_result == 0xFFFFFFFF) {
        terminal_set_color(14, 0);
        terminal_write_string("WARNING: PCI access test failed\n");
        terminal_set_color(7, 0);
        return false;
    }

    uint8_t timer_result = safe_inb(0x43);
    (void)timer_result;

    if (hardware_exception_occurred) {
        terminal_set_color(14, 0);
        terminal_write_string("WARNING: I/O port access test failed\n");
        terminal_set_color(7, 0);
        return false;
    }

    if (fault_count > 0) {
        terminal_set_color(14, 0);
        terminal_write_string("WARNING: ");
        terminal_write_uint(fault_count);
        terminal_write_string(" hardware faults detected during testing\n");
        terminal_set_color(7, 0);
    }

    terminal_set_color(10, 0);
    terminal_write_string("Hardware access test completed successfully\n");
    terminal_set_color(7, 0);

    return true;
}

bool validate_hardware_address(void* address) {
    if (!address) return false;

    uintptr_t addr = (uintptr_t)address;

    if (addr < 0x1000) return false;          // Null pointer region
    if (addr > 0xFFFFF000) return false;      // High memory region

    if (addr >= (uintptr_t)__kernel_start && addr < (uintptr_t)__kernel_end) return false;

    return true;
}

bool is_hardware_accessible(void) {
    reset_hardware_fault_status();
    uint32_t vendor_device = safe_pci_read_dword(0, 0, 0, 0);

    return !hardware_exception_occurred &&
           (vendor_device != 0x00000000) &&
           (vendor_device != 0xFFFFFFFF);
}
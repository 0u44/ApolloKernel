#ifndef RTL8139_DRIVER_H
#define RTL8139_DRIVER_H

#include "types.h"
#include "network_interface.h"

#define RTL8139_VENDOR_ID 0x10EC
#define RTL8139_DEVICE_ID 0x8139

#define RTL8139_IDR0    0x00    // MAC address
#define RTL8139_IDR1    0x01
#define RTL8139_IDR2    0x02
#define RTL8139_IDR3    0x03
#define RTL8139_IDR4    0x04
#define RTL8139_IDR5    0x05
#define RTL8139_MAR0    0x08    // Multicast registers
#define RTL8139_MAR1    0x09
#define RTL8139_MAR2    0x0A
#define RTL8139_MAR3    0x0B
#define RTL8139_MAR4    0x0C
#define RTL8139_MAR5    0x0D
#define RTL8139_MAR6    0x0E
#define RTL8139_MAR7    0x0F
#define RTL8139_TXSTATUS0 0x10  // Transmit status
#define RTL8139_TXSTATUS1 0x14
#define RTL8139_TXSTATUS2 0x18
#define RTL8139_TXSTATUS3 0x1C
#define RTL8139_TXADDR0   0x20  // Transmit start addresses
#define RTL8139_TXADDR1   0x24
#define RTL8139_TXADDR2   0x28
#define RTL8139_TXADDR3   0x2C
#define RTL8139_RXBUF     0x30  // Receive buffer start address
#define RTL8139_CHIPCMD   0x37  // Command register
#define RTL8139_CAPR      0x38  // Current address of packet read, kept 16 bytes behind
#define RTL8139_CBR       0x3A  // Current buffer address the chip writes next
#define RTL8139_IMR       0x3C  // Interrupt mask register
#define RTL8139_ISR       0x3E  // Interrupt status register
#define RTL8139_TCR       0x40  // Transmit configuration register
#define RTL8139_RCR       0x44  // Receive configuration register
#define RTL8139_TCTR      0x48  // Timer count register
#define RTL8139_MPC       0x4C  // Missed packet counter
#define RTL8139_9346CR    0x50  // 93C46 command register
#define RTL8139_CONFIG0   0x51  // Configuration register 0
#define RTL8139_CONFIG1   0x52  // Configuration register 1
#define RTL8139_MSR       0x58  // Media status register
#define RTL8139_CONFIG4   0x5A  // Configuration register 4
#define RTL8139_MULINT    0x5C  // Multiple interrupt register
#define RTL8139_RERID     0x5E  // PCI revision ID
#define RTL8139_TSAD      0x60  // Transmit status of all descriptors
#define RTL8139_BMCR      0x62  // Basic mode control register
#define RTL8139_BMSR      0x64  // Basic mode status register
#define RTL8139_ANAR      0x66  // Auto-negotiation advertisement register
#define RTL8139_ANLPAR    0x68  // Auto-negotiation link partner register
#define RTL8139_ANER      0x6A  // Auto-negotiation expansion register
#define RTL8139_DIS       0x6C  // Disconnect counter
#define RTL8139_FCSC      0x6E  // False carrier sense counter
#define RTL8139_NWAYTR    0x70  // N-way test register
#define RTL8139_REC       0x72  // RX_ER counter
#define RTL8139_CSCR      0x74  // CS configuration register
#define RTL8139_PHY1_PARM 0x78  // PHY parameter 1
#define RTL8139_TW_PARM   0x7C  // Twister parameter
#define RTL8139_PHY2_PARM 0x80  // PHY parameter 2
#define RTL8139_CR        RTL8139_CHIPCMD
#define RTL8139_CR_RST    0x10  // Reset
#define RTL8139_CR_RE     0x08  // Receiver enable
#define RTL8139_CR_TE     0x04  // Transmitter enable
#define RTL8139_CR_BUFE   0x01  // Rx buffer empty
#define RTL8139_INT_SERR  0x8000  // System error
#define RTL8139_INT_TIMEOUT 0x4000 // Time out
#define RTL8139_INT_LENCHG 0x2000  // Cable length change
#define RTL8139_INT_FOVW  0x0040  // Rx FIFO overflow
#define RTL8139_INT_PUN   0x0020  // Packet underrun
#define RTL8139_INT_RXOVW 0x0010  // Rx buffer overflow
#define RTL8139_INT_TER   0x0008  // Transmit error
#define RTL8139_INT_TOK   0x0004  // Transmit OK
#define RTL8139_INT_RER   0x0002  // Receive error
#define RTL8139_INT_ROK   0x0001  // Receive OK
#define RTL8139_TCR_IFG96     0x03000000  // Interframe gap time
#define RTL8139_TCR_IFG88     0x02000000
#define RTL8139_TCR_IFG84     0x01000000
#define RTL8139_TCR_IFG80     0x00000000
#define RTL8139_TCR_MXDMA_2048 0x00700000  // Max DMA burst size
#define RTL8139_TCR_MXDMA_1024 0x00600000
#define RTL8139_TCR_MXDMA_512  0x00500000
#define RTL8139_TCR_MXDMA_256  0x00400000
#define RTL8139_TCR_MXDMA_128  0x00300000
#define RTL8139_TCR_MXDMA_64   0x00200000
#define RTL8139_TCR_MXDMA_32   0x00100000
#define RTL8139_TCR_MXDMA_16   0x00000000
#define RTL8139_RCR_MXDMA_UNLIMITED 0x00700000  // Max DMA burst size
#define RTL8139_RCR_MXDMA_1024     0x00600000
#define RTL8139_RCR_MXDMA_512      0x00500000
#define RTL8139_RCR_MXDMA_256      0x00400000
#define RTL8139_RCR_MXDMA_128      0x00300000
#define RTL8139_RCR_MXDMA_64       0x00200000
#define RTL8139_RCR_MXDMA_32       0x00100000
#define RTL8139_RCR_MXDMA_16       0x00000000
#define RTL8139_RCR_RBLEN_64K      0x00001800  // Rx buffer length
#define RTL8139_RCR_RBLEN_32K      0x00001000
#define RTL8139_RCR_RBLEN_16K      0x00000800
#define RTL8139_RCR_RBLEN_8K       0x00000000
#define RTL8139_RCR_RXFTH_NO_THRESH 0x000000E0  // Rx FIFO threshold
#define RTL8139_RCR_RXFTH_32       0x000000C0
#define RTL8139_RCR_RXFTH_64       0x000000A0
#define RTL8139_RCR_RXFTH_128      0x00000080
#define RTL8139_RCR_RXFTH_256      0x00000060
#define RTL8139_RCR_RXFTH_512      0x00000040
#define RTL8139_RCR_RXFTH_1024     0x00000020
#define RTL8139_RCR_RXFTH_NONE     0x00000000
#define RTL8139_RCR_AAP            0x00000001  // Accept all packets (promiscuous)
#define RTL8139_RCR_APM            0x00000002  // Accept packets matching dest addr
#define RTL8139_RCR_AM             0x00000004  // Accept multicast packets
#define RTL8139_RCR_AB             0x00000008  // Accept broadcast packets
#define RTL8139_RCR_AR             0x00000010  // Accept runt packets
#define RTL8139_RCR_AER            0x00000020  // Accept error packets
#define RTL8139_RCR_WRAP           0x00000080  // Write past the ring end instead of wrapping
#define RTL8139_RX_BUFFER_SIZE    8192    // 8KB receive buffer
#define RTL8139_RX_SLACK          (16 + 1536)  // WRAP mode can write one frame past the end
#define RTL8139_TX_BUFFER_SIZE    2048    // 2KB per transmit buffer
#define RTL8139_NUM_TX_DESC       4       // Number of transmit descriptors

typedef struct rtl8139_device {
    uint16_t bus;
    uint16_t device;
    uint16_t function;
    uint16_t io_base;
    uint8_t irq;
    
    uint8_t* rx_buffer;                  // Aligned receive buffer pointer
    void* rx_buffer_raw;                 // Raw allocated buffer for freeing
    uint32_t rx_buffer_phys;             // Physical address of receive buffer
    uint16_t rx_current;                 // Current receive position
    
    uint8_t* tx_buffer[RTL8139_NUM_TX_DESC];
    uint32_t tx_buffer_phys[RTL8139_NUM_TX_DESC]; // Physical addresses
    uint8_t tx_current;
    
    uint32_t packets_received;
    uint32_t packets_transmitted;
    uint32_t rx_errors;
    uint32_t tx_errors;
    
    network_interface_t* interface;
} rtl8139_device_t;

bool rtl8139_driver_initialize(void);
rtl8139_device_t* rtl8139_find_device(uint16_t bus, uint16_t device, uint16_t function);
bool rtl8139_probe_and_initialize_device(uint16_t bus, uint16_t device_num, uint16_t function);

void rtl8139_reset(rtl8139_device_t* device);
void rtl8139_get_mac_address(rtl8139_device_t* device, mac_address_t* mac);
bool rtl8139_link_up(rtl8139_device_t* device);

bool rtl8139_send_packet(network_interface_t* iface, const void* packet, uint32_t length);
bool rtl8139_receive_packet(network_interface_t* iface, void* buffer, uint32_t* length);
bool rtl8139_set_promiscuous(network_interface_t* iface, bool enable);
bool rtl8139_get_link_status(network_interface_t* iface);

void rtl8139_dump_status(rtl8139_device_t* device);


uint32_t pci_read_config_dword(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset);
uint16_t pci_read_config_word(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset);
uint8_t pci_read_config_byte(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset);
void pci_write_config_dword(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint32_t value);
void pci_write_config_word(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint16_t value);
void pci_write_config_byte(uint16_t bus, uint16_t device, uint16_t function, uint8_t offset, uint8_t value);
bool pci_scan_for_devices(uint16_t vendor_id, uint16_t device_id);

#endif
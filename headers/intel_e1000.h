#ifndef INTEL_E1000_H
#define INTEL_E1000_H

#include "types.h"
#include "network_interface.h"

#define E1000_REG_CTRL      0x00000  // Device Control Register
#define E1000_REG_STATUS    0x00008  // Device Status Register
#define E1000_REG_EECD      0x00010  // EEPROM/Flash Control/Data
#define E1000_REG_EERD      0x00014  // EEPROM Read
#define E1000_REG_CTRL_EXT  0x00018  // Extended Device Control
#define E1000_REG_FLA       0x0001C  // Flash Access
#define E1000_REG_MDIC      0x00020  // MDI Control
#define E1000_REG_FCAL      0x00028  // Flow Control Address Low
#define E1000_REG_FCAH      0x0002C  // Flow Control Address High
#define E1000_REG_FCT       0x00030  // Flow Control Type
#define E1000_REG_VET       0x00038  // VLAN Ether Type
#define E1000_REG_ICR       0x000C0  // Interrupt Cause Read
#define E1000_REG_ITR       0x000C4  // Interrupt Throttling Rate
#define E1000_REG_ICS       0x000C8  // Interrupt Cause Set
#define E1000_REG_IMS       0x000D0  // Interrupt Mask Set
#define E1000_REG_IMC       0x000D8  // Interrupt Mask Clear
#define E1000_REG_RCTL      0x00100  // Receive Control
#define E1000_REG_FCTTV     0x00170  // Flow Control Transmit Timer Value
#define E1000_REG_TXCW      0x00178  // Transmit Config Word
#define E1000_REG_RXCW      0x00180  // Receive Config Word
#define E1000_REG_TCTL      0x00400  // Transmit Control
#define E1000_REG_TIPG      0x00410  // Transmit Inter-packet Gap
#define E1000_REG_LEDCTL    0x00E00  // LED Control
#define E1000_REG_PBA       0x01000  // Packet Buffer Allocation
#define E1000_REG_PBS       0x01008  // Packet Buffer Size
#define E1000_REG_EEMNGCTL  0x01010  // Manageability EEPROM-Mode Control
#define E1000_REG_FLASH_UPDATES 0x01034 // Flash Updates
#define E1000_REG_EEWR      0x0102C  // EEPROM Write
#define E1000_REG_FLOP      0x0103C  // Flash Opcode
#define E1000_REG_ERT       0x02008  // Early Receive Threshold
#define E1000_REG_FCRTL     0x02160  // Flow Control Receive Threshold Low
#define E1000_REG_FCRTH     0x02168  // Flow Control Receive Threshold High
#define E1000_REG_PSRCTL    0x02170  // Packet Split Receive Control
#define E1000_REG_RDBAL     0x02800  // Receive Descriptor Base Address Low
#define E1000_REG_RDBAH     0x02804  // Receive Descriptor Base Address High
#define E1000_REG_RDLEN     0x02808  // Receive Descriptor Length
#define E1000_REG_RDH       0x02810  // Receive Descriptor Head
#define E1000_REG_RDT       0x02818  // Receive Descriptor Tail
#define E1000_REG_RDTR      0x02820  // Receive Delay Timer
#define E1000_REG_RADV      0x0282C  // Receive Interrupt Absolute Delay Timer
#define E1000_REG_RSRPD     0x02C00  // Receive Small Packet Detect
#define E1000_REG_RAID      0x02C08  // Receive Acknowledge Auto-Interrupt Disable
#define E1000_REG_TXDMAC    0x03000  // Transmit DMA Control
#define E1000_REG_TADV      0x0282C  // Transmit Absolute Interrupt Delay Value
#define E1000_REG_TSPMT     0x03830  // TCP Segmentation PAD & Min Threshold
#define E1000_REG_TARC0     0x03840  // Transmit Arbitration Count (0)
#define E1000_REG_TDBAL     0x03800  // Transmit Descriptor Base Address Low
#define E1000_REG_TDBAH     0x03804  // Transmit Descriptor Base Address High
#define E1000_REG_TDLEN     0x03808  // Transmit Descriptor Length
#define E1000_REG_TDH       0x03810  // Transmit Descriptor Head
#define E1000_REG_TDT       0x03818  // Transmit Descriptor Tail
#define E1000_REG_TIDV      0x03820  // Transmit Interrupt Delay Value
#define E1000_REG_TXDCTL    0x03828  // Transmit Descriptor Control
#define E1000_REG_CRCERRS   0x04000  // CRC Error Count
#define E1000_REG_ALGNERRC  0x04004  // Alignment Error Count
#define E1000_REG_SYMERRS   0x04008  // Symbol Error Count
#define E1000_REG_RXERRC    0x0400C  // Receive Error Count
#define E1000_REG_MPC       0x04010  // Missed Packet Count
#define E1000_REG_SCC       0x04014  // Single Collision Count
#define E1000_REG_ECOL      0x04018  // Excessive Collision Count
#define E1000_REG_MCC       0x0401C  // Multiple Collision Count
#define E1000_REG_LATECOL   0x04020  // Late Collision Count
#define E1000_REG_COLC      0x04028  // Collision Count
#define E1000_REG_DC        0x04030  // Defer Count
#define E1000_REG_TNCRS     0x04034  // Transmit - No CRS
#define E1000_REG_SEC       0x04038  // Sequence Error Count
#define E1000_REG_CEXTERR   0x0403C  // Carrier Extension Error Count
#define E1000_REG_RLEC      0x04040  // Receive Length Error Count
#define E1000_REG_XONRXC    0x04048  // XON Received Count
#define E1000_REG_XONTXC    0x0404C  // XON Transmitted Count
#define E1000_REG_XOFFRXC   0x04050  // XOFF Received Count
#define E1000_REG_XOFFTXC   0x04054  // XOFF Transmitted Count
#define E1000_REG_FCRUC     0x04058  // Flow Control Received Unsupported Count
#define E1000_REG_PRC64     0x0405C  // Packets Received (64 bytes) Count
#define E1000_REG_PRC127    0x04060  // Packets Received (65-127 bytes) Count
#define E1000_REG_PRC255    0x04064  // Packets Received (128-255 bytes) Count
#define E1000_REG_PRC511    0x04068  // Packets Received (255-511 bytes) Count
#define E1000_REG_PRC1023   0x0406C  // Packets Received (512-1023 bytes) Count
#define E1000_REG_PRC1522   0x04070  // Packets Received (1024-1522 bytes)
#define E1000_REG_GPRC      0x04074  // Good Packets Received Count
#define E1000_REG_BPRC      0x04078  // Broadcast Packets Received Count
#define E1000_REG_MPRC      0x0407C  // Multicast Packets Received Count
#define E1000_REG_GPTC      0x04080  // Good Packets Transmitted Count
#define E1000_REG_GORCL     0x04088  // Good Octets Received Count Low
#define E1000_REG_GORCH     0x0408C  // Good Octets Received Count High
#define E1000_REG_GOTCL     0x04090  // Good Octets Transmitted Count Low
#define E1000_REG_GOTCH     0x04094  // Good Octets Transmitted Count High
#define E1000_REG_RNBC      0x040A0  // Receive No Buffers Count
#define E1000_REG_RUC       0x040A4  // Receive Undersize Count
#define E1000_REG_RFC       0x040A8  // Receive Fragment Count
#define E1000_REG_ROC       0x040AC  // Receive Oversize Count
#define E1000_REG_RJC       0x040B0  // Receive Jabber Count
#define E1000_REG_MGTPRC    0x040B4  // Management Packets Received Count
#define E1000_REG_MGTPDC    0x040B8  // Management Packets Dropped Count
#define E1000_REG_MGTPTC    0x040BC  // Management Packets Transmitted Count
#define E1000_REG_TORL      0x040C0  // Total Octets Received Low
#define E1000_REG_TORH      0x040C4  // Total Octets Received High
#define E1000_REG_TOTL      0x040C8  // Total Octets Transmitted Low
#define E1000_REG_TOTH      0x040CC  // Total Octets Transmitted High
#define E1000_REG_TPR       0x040D0  // Total Packets Received
#define E1000_REG_TPT       0x040D4  // Total Packets Transmitted
#define E1000_REG_PTC64     0x040D8  // Packets Transmitted (64 bytes) Count
#define E1000_REG_PTC127    0x040DC  // Packets Transmitted (65-127 bytes) Count
#define E1000_REG_PTC255    0x040E0  // Packets Transmitted (128-255 bytes) Count
#define E1000_REG_PTC511    0x040E4  // Packets Transmitted (256-511 bytes) Count
#define E1000_REG_PTC1023   0x040E8  // Packets Transmitted (512-1023 bytes) Count
#define E1000_REG_PTC1522   0x040EC  // Packets Transmitted (1024-1522 Bytes) Count
#define E1000_REG_MPTC      0x040F0  // Multicast Packets Transmitted Count
#define E1000_REG_BPTC      0x040F4  // Broadcast Packets Transmitted Count
#define E1000_REG_TSCTC     0x040F8  // TCP Segmentation Context Transmitted Count
#define E1000_REG_TSCTFC    0x040FC  // TCP Segmentation Context Tx Fail Count
#define E1000_REG_IAC       0x04100  // Interrupt Assertion Count
#define E1000_REG_ICRXPTC   0x04104  // Interrupt Cause Rx Packet Timer Expire Count
#define E1000_REG_ICRXATC   0x04108  // Interrupt Cause Rx Absolute Timer Expire Count
#define E1000_REG_ICTXPTC   0x0410C  // Interrupt Cause Tx Packet Timer Expire Count
#define E1000_REG_ICTXATC   0x04110  // Interrupt Cause Tx Absolute Timer Expire Count
#define E1000_REG_ICTXQEC   0x04118  // Interrupt Cause Tx Queue Empty Count
#define E1000_REG_ICTXQMTC  0x0411C  // Interrupt Cause Tx Queue Minimum Threshold Count
#define E1000_REG_ICRXDMTC  0x04120  // Interrupt Cause Rx Descriptor Minimum Threshold Count
#define E1000_REG_ICRXOC    0x04124  // Interrupt Cause Receiver Overrun Count
#define E1000_REG_RXDCTL    0x02828  // Receive Descriptor Control
#define E1000_REG_RAL       0x05400  // Receive Address Low
#define E1000_REG_RAH       0x05404  // Receive Address High
#define E1000_CTRL_FD       0x00000001  // Full Duplex
#define E1000_CTRL_BEM      0x00000002  // Endian Mode
#define E1000_CTRL_PRIOR    0x00000004  // Priority on PCI
#define E1000_CTRL_GIO_MASTER_DISABLE 0x00000004 // Blocks new Master requests
#define E1000_CTRL_LRST     0x00000008  // Link Reset
#define E1000_CTRL_TME      0x00000010  // Test Mode Enable
#define E1000_CTRL_SLE      0x00000020  // Serial Link Enable
#define E1000_CTRL_ASDE     0x00000020  // Auto Speed Detection Enable
#define E1000_CTRL_SLU      0x00000040  // Set Link Up
#define E1000_CTRL_ILOS     0x00000080  // Invert Loss of Signal
#define E1000_CTRL_SPD_SEL  0x00000300  // Speed Select Mask
#define E1000_CTRL_SPD_10   0x00000000  // Force 10Mb
#define E1000_CTRL_SPD_100  0x00000100  // Force 100Mb
#define E1000_CTRL_SPD_1000 0x00000200  // Force 1000Mb
#define E1000_CTRL_BEM32    0x00000400  // Big Endian 32 mode
#define E1000_CTRL_FRCSPD   0x00000800  // Force Speed
#define E1000_CTRL_FRCDPX   0x00001000  // Force Duplex
#define E1000_CTRL_D_UD_EN  0x00002000  // Dock/Undock enable
#define E1000_CTRL_D_UD_POLARITY 0x00004000 // Defined polarity of Dock/Undock indication in SDP[0]
#define E1000_CTRL_FORCE_PHY_RESET 0x00008000 // Reset both PHY ports, through PHYRST_N pin
#define E1000_CTRL_EXT_LINK_EN 0x00010000 // enable link status from external LINK_0 and LINK_1 pins
#define E1000_CTRL_SWDPIN0  0x00040000  // SWDPIN 0 value
#define E1000_CTRL_SWDPIN1  0x00080000  // SWDPIN 1 value
#define E1000_CTRL_SWDPIN2  0x00100000  // SWDPIN 2 value
#define E1000_CTRL_SWDPIN3  0x00200000  // SWDPIN 3 value
#define E1000_CTRL_SWDPIO0  0x00400000  // SWDPIN 0 Input or output
#define E1000_CTRL_SWDPIO1  0x00800000  // SWDPIN 1 input or output
#define E1000_CTRL_SWDPIO2  0x01000000  // SWDPIN 2 input or output
#define E1000_CTRL_SWDPIO3  0x02000000  // SWDPIN 3 input or output
#define E1000_CTRL_RST      0x04000000  // Global reset
#define E1000_CTRL_RFCE     0x08000000  // Receive Flow Control enable
#define E1000_CTRL_TFCE     0x10000000  // Transmit flow control enable
#define E1000_CTRL_RTE      0x20000000  // Routing tag enable
#define E1000_CTRL_VME      0x40000000  // IEEE VLAN mode enable
#define E1000_CTRL_PHY_RST  0x80000000  // PHY Reset
#define E1000_STATUS_FD         0x00000001      // Full duplex connection
#define E1000_STATUS_LU         0x00000002      // Link up
#define E1000_STATUS_FUNC_MASK  0x0000000C      // PCI Function Mask
#define E1000_STATUS_FUNC_SHIFT 2
#define E1000_STATUS_FUNC_0     0x00000000      // Function 0
#define E1000_STATUS_FUNC_1     0x00000004      // Function 1
#define E1000_STATUS_TXOFF      0x00000010      // transmission paused
#define E1000_STATUS_TBIMODE    0x00000020      // TBI mode
#define E1000_STATUS_SPEED_MASK 0x000000C0
#define E1000_STATUS_SPEED_10   0x00000000      // Speed 10Mb/s
#define E1000_STATUS_SPEED_100  0x00000040      // Speed 100Mb/s
#define E1000_STATUS_SPEED_1000 0x00000080      // Speed 1000Mb/s
#define E1000_STATUS_LAN_INIT_DONE 0x00000200   // Lan Init Completion by NVM
#define E1000_STATUS_ASDV       0x00000300      // Auto speed detect value
#define E1000_STATUS_DOCK_CI    0x00000800      // Change in Dock/Undock state
#define E1000_STATUS_GIO_MASTER_ENABLE 0x00080000 // Status of Master requests
#define E1000_STATUS_MTXCKOK    0x00000400      // MTX clock running OK
#define E1000_STATUS_PCI66      0x00000800      // In 66Mhz slot
#define E1000_STATUS_BUS64      0x00001000      // In 64 bit slot
#define E1000_STATUS_PCIX_MODE  0x00002000      // PCI-X mode
#define E1000_STATUS_PCIX_SPEED 0x0000C000      // PCI-X bus speed
#define E1000_STATUS_BMC_SKU_0  0x00100000      // BMC USB redirect disabled
#define E1000_STATUS_BMC_SKU_1  0x00200000      // BMC SRAM disabled
#define E1000_STATUS_BMC_SKU_2  0x00400000      // BMC SDRAM disabled
#define E1000_STATUS_BMC_CRYPTO 0x00800000      // BMC crypto disabled
#define E1000_STATUS_BMC_LITE   0x01000000      // BMC external code execution disabled
#define E1000_STATUS_RGMII_ENABLE 0x02000000    // RGMII disabled
#define E1000_STATUS_FUSE_8       0x04000000
#define E1000_STATUS_FUSE_9       0x08000000
#define E1000_STATUS_SERDES0_DIS  0x10000000    // SERDES disabled on port 0
#define E1000_STATUS_SERDES1_DIS  0x20000000    // SERDES disabled on port 1
#define E1000_RCTL_RST          0x00000001    // Software reset
#define E1000_RCTL_EN           0x00000002    // enable
#define E1000_RCTL_SBP          0x00000004    // store bad packet
#define E1000_RCTL_UPE          0x00000008    // unicast promiscuous enable
#define E1000_RCTL_MPE          0x00000010    // multicast promiscuous enab
#define E1000_RCTL_LPE          0x00000020    // long packet enable
#define E1000_RCTL_LBM_NO       0x00000000    // no loopback mode
#define E1000_RCTL_LBM_MAC      0x00000040    // MAC loopback mode
#define E1000_RCTL_LBM_SLP      0x00000080    // serial link loopback mode
#define E1000_RCTL_LBM_TCVR     0x000000C0    // tcvr loopback mode
#define E1000_RCTL_DTYP_MASK    0x00000C00    // Descriptor type mask
#define E1000_RCTL_DTYP_PS      0x00000400    // Packet Split descriptor
#define E1000_RCTL_RDMTS_HALF   0x00000000    // rx desc min threshold size
#define E1000_RCTL_RDMTS_QUAR   0x00000100    // rx desc min threshold size
#define E1000_RCTL_RDMTS_EIGH   0x00000200    // rx desc min threshold size
#define E1000_RCTL_MO_SHIFT     12            // multicast offset shift
#define E1000_RCTL_MO_0         0x00000000    // multicast offset 11:0
#define E1000_RCTL_MO_1         0x00001000    // multicast offset 12:1
#define E1000_RCTL_MO_2         0x00002000    // multicast offset 13:2
#define E1000_RCTL_MO_3         0x00003000    // multicast offset 15:4
#define E1000_RCTL_MDR          0x00004000    // multicast desc ring 0
#define E1000_RCTL_BAM          0x00008000    // broadcast enable
#define E1000_RCTL_SZ_2048      0x00000000    // rx buffer size 2048
#define E1000_RCTL_SZ_1024      0x00010000    // rx buffer size 1024
#define E1000_RCTL_SZ_512       0x00020000    // rx buffer size 512
#define E1000_RCTL_SZ_256       0x00030000    // rx buffer size 256
#define E1000_RCTL_SZ_16384     0x00010000    // rx buffer size 16384
#define E1000_RCTL_SZ_8192      0x00020000    // rx buffer size 8192
#define E1000_RCTL_SZ_4096      0x00030000    // rx buffer size 4096
#define E1000_RCTL_VFE          0x00040000    // vlan filter enable
#define E1000_RCTL_CFIEN        0x00080000    // canonical form enable
#define E1000_RCTL_CFI          0x00100000    // canonical form indicator
#define E1000_RCTL_DPF          0x00400000    // discard pause frames
#define E1000_RCTL_PMCF         0x00800000    // pass MAC control frames
#define E1000_RCTL_BSEX         0x02000000    // Buffer size extension
#define E1000_RCTL_SECRC        0x04000000    // Strip Ethernet CRC
#define E1000_TCTL_RST          0x00000001    // software reset
#define E1000_TCTL_EN           0x00000002    // enable tx
#define E1000_TCTL_BCE          0x00000004    // busy check enable
#define E1000_TCTL_PSP          0x00000008    // pad short packets
#define E1000_TCTL_CT           0x00000ff0    // collision threshold
#define E1000_TCTL_COLD         0x003ff000    // collision distance
#define E1000_TCTL_SWXOFF       0x00400000    // SW Xoff transmission
#define E1000_TCTL_PBE          0x00800000    // Packet Burst Enable
#define E1000_TCTL_RTLC         0x01000000    // Re-transmit on late collision
#define E1000_TCTL_NRTU         0x02000000    // No Re-transmit on underrun
#define E1000_TCTL_MULR         0x10000000    // Multiple request support
#define E1000_RAH_AV            0x80000000    // Receive descriptor valid

typedef struct {
    uint16_t vendor_id;
    uint16_t device_id;
    const char* name;
} intel_device_id_t;

#define E1000_REG_MTA       0x05200  // Multicast table array, 128 entries
#define E1000_RX_DESCRIPTORS 32
#define E1000_TX_DESCRIPTORS 8
#define E1000_BUFFER_SIZE 2048

typedef struct {
    uint64_t address;
    uint16_t length;
    uint16_t checksum;
    uint8_t status;
    uint8_t errors;
    uint16_t special;
} __attribute__((packed)) e1000_rx_descriptor_t;

typedef struct {
    uint64_t address;
    uint16_t length;
    uint8_t checksum_offset;
    uint8_t command;
    uint8_t status;
    uint8_t checksum_start;
    uint16_t special;
} __attribute__((packed)) e1000_tx_descriptor_t;

typedef struct intel_e1000_device {
    uint16_t bus;
    uint16_t device;
    uint16_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    
    bool use_io;
    union {
        uintptr_t mem_base;
        uint16_t io_base;    // I/O port base (legacy)
    };
    
    network_interface_t* interface;

    e1000_rx_descriptor_t* rx_ring;
    e1000_tx_descriptor_t* tx_ring;
    uint8_t* rx_buffers[E1000_RX_DESCRIPTORS];
    uint8_t* tx_buffers[E1000_TX_DESCRIPTORS];
    uint32_t rx_next;
    uint32_t tx_next;

    uint32_t packets_received;
    uint32_t packets_transmitted;
    uint32_t rx_errors;
    uint32_t tx_errors;
} intel_e1000_device_t;

bool intel_e1000_driver_initialize(void);
bool intel_e1000_supports(uint16_t vendor_id, uint16_t device_id);
intel_e1000_device_t* intel_e1000_find_device(uint16_t bus, uint16_t device, uint16_t function);
bool intel_e1000_probe_and_initialize_device(uint16_t bus, uint16_t device, uint16_t function);
void intel_e1000_dump_device_info(intel_e1000_device_t* device);

#endif
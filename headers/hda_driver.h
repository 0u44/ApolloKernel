#ifndef APOLLO_HDA_DRIVER_H
#define APOLLO_HDA_DRIVER_H

#include "types.h"
#include "pci_scan.h"

// Intel HD Audio PCI IDs
#define HDA_VENDOR_INTEL        0x8086
#define HDA_DEVICE_ICH6         0x2668
#define HDA_DEVICE_ICH7         0x27D8
#define HDA_DEVICE_ICH8         0x284B
#define HDA_DEVICE_ICH9         0x293E
#define HDA_DEVICE_ICH10        0x3A3E
#define HDA_DEVICE_PCH          0x3B56
#define HDA_DEVICE_PCH_M        0x3B57
#define HDA_DEVICE_BAYTRAIL     0x0F04
#define HDA_DEVICE_BRASWELL     0x2284
#define HDA_DEVICE_SKYLAKE      0xA170
#define HDA_DEVICE_KABYLAKE     0xA171

// HDA Register Offsets
#define HDA_REG_GCAP            0x00    // Global Capabilities
#define HDA_REG_VMIN            0x02    // Minor Version
#define HDA_REG_VMAJ            0x03    // Major Version  
#define HDA_REG_OUTPAY          0x04    // Output Payload Capability
#define HDA_REG_INPAY           0x06    // Input Payload Capability
#define HDA_REG_GCTL            0x08    // Global Control
#define HDA_REG_WAKEEN          0x0C    // Wake Enable
#define HDA_REG_STATESTS        0x0E    // State Change Status
#define HDA_REG_GSTS            0x10    // Global Status
#define HDA_REG_OUTSTRMPAY      0x18    // Output Stream Payload Capability
#define HDA_REG_INSTRMPAY       0x1A    // Input Stream Payload Capability
#define HDA_REG_INTCTL          0x20    // Interrupt Control
#define HDA_REG_INTSTS          0x24    // Interrupt Status
#define HDA_REG_WALCLK          0x30    // Wall Clock Counter
#define HDA_REG_SYNC            0x34    // Stream Synchronization
#define HDA_REG_CORBLBASE       0x40    // CORB Lower Base Address
#define HDA_REG_CORBUBASE       0x44    // CORB Upper Base Address
#define HDA_REG_CORBWP          0x48    // CORB Write Pointer
#define HDA_REG_CORBRP          0x4A    // CORB Read Pointer
#define HDA_REG_CORBCTL         0x4C    // CORB Control
#define HDA_REG_CORBSTS         0x4D    // CORB Status
#define HDA_REG_CORBSIZE        0x4E    // CORB Size
#define HDA_REG_RIRBLBASE       0x50    // RIRB Lower Base Address
#define HDA_REG_RIRBUBASE       0x54    // RIRB Upper Base Address
#define HDA_REG_RIRBWP          0x58    // RIRB Write Pointer
#define HDA_REG_RINTCNT         0x5A    // Response Interrupt Count
#define HDA_REG_RIRBCTL         0x5C    // RIRB Control
#define HDA_REG_RIRBSTS         0x5D    // RIRB Status
#define HDA_REG_RIRBSIZE        0x5E    // RIRB Size

// Stream Descriptor Registers (for stream 0, add 0x20 for each stream)
#define HDA_REG_SD0CTL          0x80    // Stream Descriptor Control
#define HDA_REG_SD0STS          0x83    // Stream Descriptor Status  
#define HDA_REG_SD0LPIB         0x84    // Link Position in Buffer
#define HDA_REG_SD0CBL          0x88    // Cyclic Buffer Length
#define HDA_REG_SD0LVI          0x8C    // Last Valid Index
#define HDA_REG_SD0FIFOD        0x90    // FIFO Size
#define HDA_REG_SD0FMT          0x92    // Stream Format
#define HDA_REG_SD0BDPL         0x98    // Buffer Descriptor List Pointer Lower
#define HDA_REG_SD0BDPU         0x9C    // Buffer Descriptor List Pointer Upper

// Global Control Register Bits
#define HDA_GCTL_RESET          0x01    // Controller Reset
#define HDA_GCTL_FCNTRL         0x02    // Flush Control
#define HDA_GCTL_UNSOL          0x08    // Unsolicited Response Enable

// Stream Control Register Bits
#define HDA_SDCTL_SRST          0x01    // Stream Reset
#define HDA_SDCTL_RUN           0x02    // Stream Run
#define HDA_SDCTL_IOCE          0x04    // Interrupt On Completion Enable
#define HDA_SDCTL_FEIE          0x08    // FIFO Error Interrupt Enable
#define HDA_SDCTL_DEIE          0x10    // Descriptor Error Interrupt Enable

// CORB/RIRB Control Bits
#define HDA_CORBCTL_RUN         0x02    // CORB DMA Enable
#define HDA_RIRBCTL_RUN         0x02    // RIRB DMA Enable
#define HDA_RIRBCTL_RINTCTL     0x01    // Response Interrupt Control

// Buffer sizes
#define HDA_CORB_SIZE           256     // CORB entries
#define HDA_RIRB_SIZE           256     // RIRB entries  
#define HDA_MAX_STREAMS         16      // Maximum streams
#define HDA_BDL_MAX_ENTRIES     256     // Buffer Descriptor List max entries
#define HDA_BUFFER_SIZE         (64 * 1024)  // 64KB audio buffer per stream

// Audio Formats
#define HDA_FMT_PCM             0x0000
#define HDA_FMT_8BIT            0x0000
#define HDA_FMT_16BIT           0x0010  
#define HDA_FMT_20BIT           0x0020
#define HDA_FMT_24BIT           0x0030
#define HDA_FMT_32BIT           0x0040
#define HDA_FMT_8KHZ            0x0000
#define HDA_FMT_11KHZ           0x0001
#define HDA_FMT_16KHZ           0x0002
#define HDA_FMT_22KHZ           0x0003
#define HDA_FMT_32KHZ           0x0004
#define HDA_FMT_44KHZ           0x0005
#define HDA_FMT_48KHZ           0x0006
#define HDA_FMT_88KHZ           0x0007
#define HDA_FMT_96KHZ           0x0008
#define HDA_FMT_176KHZ          0x0009
#define HDA_FMT_192KHZ          0x000A
#define HDA_FMT_MONO            0x0000
#define HDA_FMT_STEREO          0x0001

#define HDA_MAX_CODECS          15
#define HDA_AMP_SET_OUTPUT      0x8000
#define HDA_AMP_SET_INPUT       0x4000
#define HDA_AMP_SET_BOTH        0x3000  // Left and right channels
#define HDA_AMP_MUTE            0x0080
#define HDA_AMP_GAIN_MASK       0x007F
#define HDA_DEFAULT_GAIN        0x50
#define HDA_PIN_OUT_ENABLE      0x40
#define HDA_PIN_IN_ENABLE       0x20

// Codec Commands
#define HDA_CODEC_CMD(cad, nid, direct, verb, parm) \
    (((uint32_t)(cad) << 28) | ((uint32_t)(direct) << 27) | \
     ((uint32_t)(nid) << 20) | ((uint32_t)(verb) << 8) | ((uint32_t)(parm)))

// Common Verbs
#define HDA_VERB_GET_PARAM              0xF00
#define HDA_VERB_GET_CONN_SELECT        0xF01
#define HDA_VERB_SET_CONN_SELECT        0x701
#define HDA_VERB_GET_CONN_LIST          0xF02
#define HDA_VERB_GET_PROC_STATE         0xF03
#define HDA_VERB_SET_PROC_STATE         0x703
#define HDA_VERB_GET_SDI_SELECT         0xF04
#define HDA_VERB_SET_SDI_SELECT         0x704
#define HDA_VERB_GET_POWER_STATE        0xF05
#define HDA_VERB_SET_POWER_STATE        0x705
#define HDA_VERB_GET_STREAM_FORMAT      0xA00
#define HDA_VERB_SET_STREAM_FORMAT      0x200
#define HDA_VERB_GET_AMP_GAIN_MUTE      0xB00
#define HDA_VERB_SET_AMP_GAIN_MUTE      0x300
#define HDA_VERB_GET_CONV_CTRL          0xF06
#define HDA_VERB_SET_CONV_CTRL          0x706
#define HDA_VERB_GET_PIN_CTRL           0xF07
#define HDA_VERB_SET_PIN_CTRL           0x707
#define HDA_VERB_GET_UNSOL_RESP         0xF08
#define HDA_VERB_SET_UNSOL_RESP         0x708
#define HDA_VERB_GET_PIN_SENSE          0xF09
#define HDA_VERB_EXEC_PIN_SENSE         0x709

// Buffer Descriptor Entry
typedef struct {
    uint64_t address;
    uint32_t length;            // Length of buffer in bytes
    uint32_t flags;             // IOC (Interrupt on Completion) flag
} __attribute__((packed)) hda_bdl_entry_t;

// CORB Entry (Command Output Ring Buffer)
typedef struct {
    uint32_t command;
} __attribute__((packed)) hda_corb_entry_t;

// RIRB Entry (Response Input Ring Buffer) 
typedef struct {
    uint64_t response;          // Codec response (32-bit response + 32-bit flags)
} __attribute__((packed)) hda_rirb_entry_t;

typedef struct {
    uint8_t stream_id;          // Stream ID (1-15)
    uint8_t stream_tag;         // Stream tag for codec communication
    bool is_output;
    bool is_active;
    uint16_t format;            // Stream format register value
    uint32_t sample_rate;       // Sample rate in Hz
    uint8_t channels;
    uint8_t bits_per_sample;    // Bits per sample (8, 16, 20, 24, 32)
    
    uint8_t* buffer;
    uintptr_t buffer_phys;
    uint32_t buffer_size;       // Total buffer size in bytes
    uint32_t period_size;       // Period size in bytes
    uint32_t periods;
    
    hda_bdl_entry_t* bdl;
    uintptr_t bdl_phys;
    uint32_t bdl_entries;
    
    uint32_t position;          // Software read or write offset in the ring
    uint32_t last_position;     // Last LPIB value seen
    uint64_t frames_played;
    uint64_t bytes_queued;
    uint64_t bytes_consumed;
    uint32_t underruns;
    uint8_t sd_index;           // Descriptor index, output streams follow the input ones
    void* buffer_raw;
    void* bdl_raw;
} hda_stream_t;

typedef struct {
    uint8_t codec_id;           // Codec Address (0-14)
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t revision;
    bool is_present;
    
    uint8_t audio_function_group;   // Audio Function Group node ID
    uint8_t output_nodes[8];        // Output converter node IDs
    uint8_t input_nodes[8];         // Input converter node IDs
    uint8_t pin_nodes[16];          // Pin complex node IDs
    uint8_t num_outputs;
    uint8_t num_inputs;
    uint8_t num_pins;
    
    uint32_t pcm_formats;
    uint32_t pcm_rates;
    uint8_t max_channels_out;
    uint8_t max_channels_in;
} hda_codec_t;

typedef struct hda_controller {
    uint16_t bus;
    uint16_t device;
    uint16_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    
    uint8_t* mmio_base;
    uint32_t mmio_phys;
    uint32_t mmio_size;
    
    uint16_t gcap;              // Global Capabilities
    uint8_t num_output_streams;
    uint8_t num_input_streams;
    uint8_t num_bidirect_streams;
    uint8_t num_codecs;
    
    hda_corb_entry_t* corb;     // Command Output Ring Buffer
    uint32_t corb_phys;
    uint16_t corb_wp;
    uint16_t corb_rp;
    
    hda_rirb_entry_t* rirb;     // Response Input Ring Buffer  
    uint32_t rirb_phys;
    uint16_t rirb_wp;
    uint16_t rirb_rp;
    
    hda_stream_t streams[HDA_MAX_STREAMS];
    hda_codec_t codecs[HDA_MAX_CODECS];     // Indexed by codec address
    
    bool is_initialized;
    bool controller_reset;
    uint32_t irq_line;
    
    uint32_t interrupts_handled;
    uint32_t corb_commands_sent;
    uint32_t rirb_responses_received;
    uint32_t stream_interrupts;
} hda_controller_t;

bool hda_driver_initialize(void);
bool hda_probe_controller(uint16_t bus, uint16_t device, uint16_t function);
bool hda_controller_reset(hda_controller_t* controller);
bool hda_controller_init_corb_rirb(hda_controller_t* controller);
bool hda_detect_codecs(hda_controller_t* controller);

// Codec Communication
bool hda_send_command(hda_controller_t* controller, uint32_t command);
bool hda_get_response(hda_controller_t* controller, uint64_t* response);
bool hda_codec_read(hda_controller_t* controller, uint8_t codec_id, uint8_t node_id, 
                   uint16_t verb, uint32_t param, uint32_t* result);
bool hda_codec_write(hda_controller_t* controller, uint8_t codec_id, uint8_t node_id,
                    uint16_t verb, uint32_t param);

// Stream Management  
bool hda_stream_setup(hda_controller_t* controller, uint8_t stream_id, 
                     bool is_output, uint32_t sample_rate, uint8_t channels, 
                     uint8_t bits_per_sample, uint32_t buffer_size);
bool hda_stream_start(hda_controller_t* controller, uint8_t stream_id);
bool hda_stream_stop(hda_controller_t* controller, uint8_t stream_id);
uint32_t hda_stream_get_position(hda_controller_t* controller, uint8_t stream_id);
bool hda_stream_write_data(hda_controller_t* controller, uint8_t stream_id,
                          const void* data, uint32_t size);
uint32_t hda_stream_write(hda_controller_t* controller, uint8_t stream_id, const void* data, uint32_t size);
uint32_t hda_stream_read(hda_controller_t* controller, uint8_t stream_id, void* data, uint32_t size);
uint32_t hda_stream_free_bytes(hda_controller_t* controller, uint8_t stream_id);
uint32_t hda_stream_queued_bytes(hda_controller_t* controller, uint8_t stream_id);
void hda_stream_release(hda_controller_t* controller, uint8_t stream_id);

// Codec Configuration
bool hda_codec_init(hda_controller_t* controller, uint8_t codec_id);  
bool hda_codec_enumerate_nodes(hda_controller_t* controller, uint8_t codec_id);
bool hda_codec_setup_output_path(hda_controller_t* controller, uint8_t codec_id);
bool hda_codec_setup_input_path(hda_controller_t* controller, uint8_t codec_id);
bool hda_codec_set_volume(hda_controller_t* controller, uint8_t codec_id, 
                         uint8_t node_id, uint8_t volume);

// Interrupt Handler
void hda_interrupt_handler(void);

// Debug and Status
void hda_dump_controller_info(hda_controller_t* controller);
void hda_dump_codec_info(hda_controller_t* controller, uint8_t codec_id);
void hda_dump_stream_info(hda_controller_t* controller, uint8_t stream_id);

extern hda_controller_t* g_hda_controller;

#endif
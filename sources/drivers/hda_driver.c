#include "hda_driver.h"
#include "terminal.h"
#include "heap_allocator.h"
#include "safe_hardware.h"
#include "time_keeper.h"
#include "pci_scan.h"
#include "types.h"

hda_controller_t* g_hda_controller = NULL;

static void hda_memset(void* dest, uint8_t value, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) {
        d[i] = value;
    }
}

static uint32_t hda_read32(hda_controller_t* controller, uint16_t offset) {
    return safe_mmio_read32((volatile uint32_t*)(uintptr_t)(controller->mmio_phys + offset));
}

static uint16_t hda_read16(hda_controller_t* controller, uint16_t offset) {
    return safe_mmio_read16((volatile uint16_t*)(uintptr_t)(controller->mmio_phys + offset));
}

static uint8_t hda_read8(hda_controller_t* controller, uint16_t offset) {
    return safe_mmio_read8((volatile uint8_t*)(uintptr_t)(controller->mmio_phys + offset));
}

static void hda_write32(hda_controller_t* controller, uint16_t offset, uint32_t value) {
    safe_mmio_write32((volatile uint32_t*)(uintptr_t)(controller->mmio_phys + offset), value);
}

static void hda_write16(hda_controller_t* controller, uint16_t offset, uint16_t value) {
    safe_mmio_write16((volatile uint16_t*)(uintptr_t)(controller->mmio_phys + offset), value);
}

static void hda_write8(hda_controller_t* controller, uint16_t offset, uint8_t value) {
    safe_mmio_write8((volatile uint8_t*)(uintptr_t)(controller->mmio_phys + offset), value);
}

static void hda_delay_ms(uint32_t milliseconds) {
    time_keeper_delay_ms(milliseconds);
}

static void hda_delay_us(uint32_t microseconds) {
    time_keeper_delay_us(microseconds);
}

#define PCI_CLASS_MULTIMEDIA 0x04
#define PCI_SUBCLASS_HDA 0x03
#define HDA_SCAN_MAX_DEVICES 64

// Probes the first HD Audio controller on the PCI bus
bool hda_driver_initialize(void) {
    if (g_hda_controller && g_hda_controller->is_initialized) {
        return true;
    }

    pci_device_t devices[HDA_SCAN_MAX_DEVICES];
    uint32_t count = pci_enumerate(devices, HDA_SCAN_MAX_DEVICES);
    for (uint32_t i = 0; i < count; i++) {
        if (devices[i].class_code != PCI_CLASS_MULTIMEDIA || devices[i].subclass != PCI_SUBCLASS_HDA) {
            continue;
        }
        terminal_write_string("HDA: Controller at ");
        terminal_write_uint(devices[i].bus);
        terminal_write_string(":");
        terminal_write_uint(devices[i].device);
        terminal_write_string(".");
        terminal_write_uint(devices[i].function);
        terminal_write_string("\n");
        return hda_probe_controller(devices[i].bus, devices[i].device, devices[i].function);
    }

    terminal_write_string("HDA: No HD Audio controller on the PCI bus\n");
    return false;
}

bool hda_probe_controller(uint16_t bus, uint16_t device, uint16_t function) {
    hda_controller_t* controller = (hda_controller_t*)apollo_allocate_memory(sizeof(hda_controller_t));
    if (!controller) {
        terminal_write_string("HDA: Failed to allocate controller structure\n");
        return false;
    }
    
    hda_memset(controller, 0, sizeof(hda_controller_t));
    
    controller->bus = bus;
    controller->device = device;
    controller->function = function;
    controller->vendor_id = pci_read_config_word(bus, device, function, 0x00);
    controller->device_id = pci_read_config_word(bus, device, function, 0x02);
    
    uint16_t command = pci_read_config_word(bus, device, function, 0x04);
    command |= 0x06;  // Enable memory space and bus mastering
    pci_write_config_word(bus, device, function, 0x04, command);
    
    // Get memory-mapped I/O base address (BAR0)
    uint32_t bar0 = pci_read_config_dword(bus, device, function, 0x10);
    if (!(bar0 & 0x01)) {
        controller->mmio_phys = bar0 & 0xFFFFFFF0;
        controller->mmio_base = (uint8_t*)(uintptr_t)controller->mmio_phys;  // Covered by the 4GB identity map from boot
        controller->mmio_size = 16384;  // 16KB MMIO space
        
        terminal_write_string("HDA: MMIO Base Address: ");
        terminal_write_hex(controller->mmio_phys);
        terminal_write_string("\n");
    } else {
        terminal_write_string("HDA: Invalid BAR0 - not memory-mapped\n");
        apollo_free_memory(controller);
        return false;
    }
    
    controller->irq_line = pci_read_config_byte(bus, device, function, 0x3C);
    terminal_write_string("HDA: IRQ Line: ");
    terminal_write_uint(controller->irq_line);
    terminal_write_string("\n");
    
    g_hda_controller = controller;
    
    if (!hda_controller_reset(controller)) {
        terminal_write_string("HDA: Controller reset failed\n");
        apollo_free_memory(controller);
        g_hda_controller = NULL;
        return false;
    }
    
    controller->gcap = hda_read16(controller, HDA_REG_GCAP);
    controller->num_output_streams = (controller->gcap >> 12) & 0x0F;
    controller->num_input_streams = (controller->gcap >> 8) & 0x0F;
    controller->num_bidirect_streams = (controller->gcap >> 3) & 0x0F;
    
    terminal_write_string("HDA: Output Streams: ");
    terminal_write_uint(controller->num_output_streams);
    terminal_write_string(", Input Streams: ");
    terminal_write_uint(controller->num_input_streams);
    terminal_write_string(", Bidirectional: ");
    terminal_write_uint(controller->num_bidirect_streams);
    terminal_write_string("\n");
    
    if (!hda_controller_init_corb_rirb(controller)) {
        terminal_write_string("HDA: CORB/RIRB initialization failed\n");
        apollo_free_memory(controller);
        g_hda_controller = NULL;
        return false;
    }
    
    hda_write32(controller, HDA_REG_INTCTL, 0x80000000 | (1 << 31) | (1 << 30));
    
    hda_delay_ms(10);
    
    if (!hda_detect_codecs(controller)) {
        terminal_write_string("HDA: No codecs detected\n");
        apollo_free_memory(controller);
        g_hda_controller = NULL;
        return false;
    }
    
    controller->is_initialized = true;
    
    terminal_write_string("HDA: Controller initialization complete\n");
    return true;
}

bool hda_controller_reset(hda_controller_t* controller) {
    terminal_write_string("HDA: Resetting controller...\n");
    
    hda_write32(controller, HDA_REG_GCTL, 0);
    hda_delay_ms(10);
    
    uint32_t timeout = 1000;
    while (timeout-- && (hda_read32(controller, HDA_REG_GCTL) & HDA_GCTL_RESET)) {
        hda_delay_us(100);
    }
    
    if (timeout == 0) {
        terminal_write_string("HDA: Controller reset timeout\n");
        return false;
    }
    
    hda_write32(controller, HDA_REG_GCTL, HDA_GCTL_RESET);
    
    timeout = 1000;
    while (timeout-- && !(hda_read32(controller, HDA_REG_GCTL) & HDA_GCTL_RESET)) {
        hda_delay_us(100);
    }
    
    if (timeout == 0) {
        terminal_write_string("HDA: Controller ready timeout\n");
        return false;
    }
    
    uint32_t gctl = hda_read32(controller, HDA_REG_GCTL);
    hda_write32(controller, HDA_REG_GCTL, gctl | HDA_GCTL_UNSOL);
    
    controller->controller_reset = true;
    terminal_write_string("HDA: Controller reset complete\n");
    return true;
}

#define HDA_RING_ALIGN 128
#define HDA_RING_SIZE_256 0x02
#define HDA_POINTER_RESET 0x8000
#define HDA_RING_INDEX_MASK 0xFF
#define HDA_RIRBSTS_CLEAR 0x05

static void* alloc_ring(uint32_t size) {
    uint8_t* raw = apollo_allocate_memory(size + HDA_RING_ALIGN);
    if (!raw) return NULL;
    uint8_t* ring = (uint8_t*)(((uintptr_t)raw + HDA_RING_ALIGN - 1) & ~(uintptr_t)(HDA_RING_ALIGN - 1));
    hda_memset(ring, 0, size);
    return ring;
}

// Rings stay allocated for the life of the controller, so the unaligned base is not kept
bool hda_controller_init_corb_rirb(hda_controller_t* controller) {
    controller->corb = alloc_ring(sizeof(hda_corb_entry_t) * HDA_CORB_SIZE);
    controller->rirb = alloc_ring(sizeof(hda_rirb_entry_t) * HDA_RIRB_SIZE);
    if (!controller->corb || !controller->rirb) {
        terminal_write_string("HDA: Failed to allocate CORB or RIRB\n");
        return false;
    }
    controller->corb_phys = (uint32_t)(uintptr_t)controller->corb;  // Heap is identity mapped
    controller->rirb_phys = (uint32_t)(uintptr_t)controller->rirb;

    hda_write8(controller, HDA_REG_CORBCTL, 0);
    hda_write8(controller, HDA_REG_RIRBCTL, 0);
    hda_delay_ms(1);

    hda_write32(controller, HDA_REG_CORBLBASE, controller->corb_phys);
    hda_write32(controller, HDA_REG_CORBUBASE, 0);
    hda_write8(controller, HDA_REG_CORBSIZE, HDA_RING_SIZE_256);
    hda_write16(controller, HDA_REG_CORBWP, 0);
    hda_write16(controller, HDA_REG_CORBRP, HDA_POINTER_RESET);
    hda_delay_us(10);
    hda_write16(controller, HDA_REG_CORBRP, 0);

    hda_write32(controller, HDA_REG_RIRBLBASE, controller->rirb_phys);
    hda_write32(controller, HDA_REG_RIRBUBASE, 0);
    hda_write8(controller, HDA_REG_RIRBSIZE, HDA_RING_SIZE_256);
    hda_write16(controller, HDA_REG_RIRBWP, HDA_POINTER_RESET);
    hda_write16(controller, HDA_REG_RINTCNT, 1);

    hda_write8(controller, HDA_REG_CORBCTL, HDA_CORBCTL_RUN);
    hda_write8(controller, HDA_REG_RIRBCTL, HDA_RIRBCTL_RUN | HDA_RIRBCTL_RINTCTL);

    controller->corb_wp = 0;
    controller->corb_rp = 0;
    controller->rirb_wp = 0;
    controller->rirb_rp = 0;
    return true;
}

bool hda_detect_codecs(hda_controller_t* controller) {
    terminal_write_string("HDA: Detecting audio codecs...\n");
    
    hda_delay_ms(100);
    
    // Check STATESTS register for codec presence
    uint16_t statests = hda_read16(controller, HDA_REG_STATESTS);
    
    terminal_write_string("HDA: STATESTS = ");
    terminal_write_hex(statests);
    terminal_write_string("\n");
    
    if (statests == 0) {
        terminal_write_string("HDA: No codecs detected via STATESTS\n");
        return false;
    }
    
    controller->num_codecs = 0;
    
    for (uint8_t codec_id = 0; codec_id < 15; codec_id++) {
        if (statests & (1 << codec_id)) {
            terminal_write_string("HDA: Probing codec ");
            terminal_write_uint(codec_id);
            terminal_write_string("...\n");
            
            uint32_t vendor_id;
            if (hda_codec_read(controller, codec_id, 0, HDA_VERB_GET_PARAM, 0x00, &vendor_id)) {
                controller->codecs[codec_id].is_present = true;
                controller->codecs[codec_id].codec_id = codec_id;
                controller->codecs[codec_id].vendor_id = (vendor_id >> 16) & 0xFFFF;
                controller->codecs[codec_id].device_id = vendor_id & 0xFFFF;
                controller->num_codecs++;
                
                terminal_write_string("HDA: Codec ");
                terminal_write_uint(codec_id);
                terminal_write_string(" - Vendor: ");
                terminal_write_hex(controller->codecs[codec_id].vendor_id);
                terminal_write_string(", Device: ");
                terminal_write_hex(controller->codecs[codec_id].device_id);
                terminal_write_string("\n");
                
                hda_codec_init(controller, codec_id);
            }
        }
    }
    
    if (controller->num_codecs == 0) {
        terminal_write_string("HDA: No responsive codecs found\n");
        return false;
    }
    
    terminal_write_string("HDA: Found ");
    terminal_write_uint(controller->num_codecs);
    terminal_write_string(" codec(s)\n");
    return true;
}

// CORBWP and RIRBWP name the last entry written, so the next entry is one past them
bool hda_send_command(hda_controller_t* controller, uint32_t command) {
    uint16_t next_wp = (controller->corb_wp + 1) % HDA_CORB_SIZE;
    uint16_t hw_rp = hda_read16(controller, HDA_REG_CORBRP) & HDA_RING_INDEX_MASK;
    if (next_wp == hw_rp) {
        terminal_write_string("HDA: CORB full\n");
        return false;
    }
    controller->corb[next_wp].command = command;
    hda_write16(controller, HDA_REG_CORBWP, next_wp);
    controller->corb_wp = next_wp;
    controller->corb_commands_sent++;
    return true;
}

bool hda_get_response(hda_controller_t* controller, uint64_t* response) {
    uint32_t timeout = 1000;
    while (timeout--) {
        uint16_t hw_wp = hda_read16(controller, HDA_REG_RIRBWP) & HDA_RING_INDEX_MASK;
        if (hw_wp != controller->rirb_rp) {
            controller->rirb_rp = (controller->rirb_rp + 1) % HDA_RIRB_SIZE;
            *response = controller->rirb[controller->rirb_rp].response;
            controller->rirb_responses_received++;
            // The controller holds further commands until the response flag is cleared
            hda_write8(controller, HDA_REG_RIRBSTS, HDA_RIRBSTS_CLEAR);
            return true;
        }
        hda_delay_us(10);
    }
    terminal_write_string("HDA: Response timeout\n");
    return false;
}

bool hda_codec_read(hda_controller_t* controller, uint8_t codec_id, uint8_t node_id, 
                   uint16_t verb, uint32_t param, uint32_t* result) {
    uint32_t command = HDA_CODEC_CMD(codec_id, node_id, 0, verb, param);
    
    if (!hda_send_command(controller, command)) {
        return false;
    }
    
    uint64_t response;
    if (!hda_get_response(controller, &response)) {
        return false;
    }
    
    *result = (uint32_t)(response & 0xFFFFFFFF);
    return true;
}

bool hda_codec_write(hda_controller_t* controller, uint8_t codec_id, uint8_t node_id,
                    uint16_t verb, uint32_t param) {
    uint32_t command = HDA_CODEC_CMD(codec_id, node_id, 0, verb, param);
    
    if (!hda_send_command(controller, command)) {
        return false;
    }
    
    // Drain the RIRB after writes even though no response is needed
    uint64_t response;
    hda_get_response(controller, &response);
    
    return true;
}

bool hda_codec_init(hda_controller_t* controller, uint8_t codec_id) {
    terminal_write_string("HDA: Initializing codec ");
    terminal_write_uint(codec_id);
    terminal_write_string("...\n");
    
    hda_codec_t* codec = &controller->codecs[codec_id];
    
    uint32_t revision;
    if (hda_codec_read(controller, codec_id, 0, HDA_VERB_GET_PARAM, 0x02, &revision)) {
        codec->revision = revision & 0xFF;
    }
    
    if (!hda_codec_enumerate_nodes(controller, codec_id)) {
        terminal_write_string("HDA: Failed to enumerate codec nodes\n");
        return false;
    }
    
    if (!hda_codec_setup_output_path(controller, codec_id)) {
        terminal_write_string("HDA: Failed to setup output path\n");
        return false;
    }
    
    terminal_write_string("HDA: Codec ");
    terminal_write_uint(codec_id);
    terminal_write_string(" initialization complete\n");
    
    return true;
}

bool hda_codec_enumerate_nodes(hda_controller_t* controller, uint8_t codec_id) {
    hda_codec_t* codec = &controller->codecs[codec_id];
    
    // Get subordinate node count and starting node ID
    uint32_t subordinate_info;
    if (!hda_codec_read(controller, codec_id, 0, HDA_VERB_GET_PARAM, 0x04, &subordinate_info)) {
        return false;
    }
    
    uint8_t start_nid = (subordinate_info >> 16) & 0xFF;
    uint8_t total_nodes = subordinate_info & 0xFF;
    
    terminal_write_string("HDA: Codec has ");
    terminal_write_uint(total_nodes);
    terminal_write_string(" nodes starting at ");
    terminal_write_uint(start_nid);
    terminal_write_string("\n");
    
    // Usually there's one Audio Function Group
    if (total_nodes > 0) {
        codec->audio_function_group = start_nid;
        
        uint32_t fg_type;
        if (hda_codec_read(controller, codec_id, start_nid, HDA_VERB_GET_PARAM, 0x05, &fg_type)) {
            if ((fg_type & 0xFF) == 0x01) {  // Audio Function Group
                terminal_write_string("HDA: Found Audio Function Group at node ");
                terminal_write_uint(start_nid);
                terminal_write_string("\n");
                
                uint32_t widget_info;
                if (hda_codec_read(controller, codec_id, start_nid, HDA_VERB_GET_PARAM, 0x04, &widget_info)) {
                    uint8_t widget_start = (widget_info >> 16) & 0xFF;
                    uint8_t widget_count = widget_info & 0xFF;
                    
                    terminal_write_string("HDA: Function group has ");
                    terminal_write_uint(widget_count);
                    terminal_write_string(" widgets starting at ");
                    terminal_write_uint(widget_start);
                    terminal_write_string("\n");
                    
                    for (uint8_t nid = widget_start; nid < widget_start + widget_count; nid++) {
                        uint32_t widget_caps;
                        if (hda_codec_read(controller, codec_id, nid, HDA_VERB_GET_PARAM, 0x09, &widget_caps)) {
                            uint8_t widget_type = (widget_caps >> 20) & 0x0F;
                            
                            switch (widget_type) {
                                case 0x0:  // Audio Output
                                    if (codec->num_outputs < 8) {
                                        codec->output_nodes[codec->num_outputs++] = nid;
                                        terminal_write_string("HDA: Output node ");
                                        terminal_write_uint(nid);
                                        terminal_write_string("\n");
                                    }
                                    break;
                                case 0x1:  // Audio Input
                                    if (codec->num_inputs < 8) {
                                        codec->input_nodes[codec->num_inputs++] = nid;
                                        terminal_write_string("HDA: Input node ");
                                        terminal_write_uint(nid);
                                        terminal_write_string("\n");
                                    }
                                    break;
                                case 0x4:  // Pin Complex
                                    if (codec->num_pins < 16) {
                                        codec->pin_nodes[codec->num_pins++] = nid;
                                        terminal_write_string("HDA: Pin node ");
                                        terminal_write_uint(nid);
                                        terminal_write_string("\n");
                                    }
                                    break;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return true;
}

// Uses the last pin for input so the first pin stays the output
bool hda_codec_setup_input_path(hda_controller_t* controller, uint8_t codec_id) {
    hda_codec_t* codec = &controller->codecs[codec_id];
    if (codec->num_inputs == 0 || codec->num_pins == 0) {
        return false;
    }
    uint8_t input_nid = codec->input_nodes[0];
    uint8_t pin_nid = codec->pin_nodes[codec->num_pins - 1];
    if (!hda_codec_write(controller, codec_id, pin_nid, HDA_VERB_SET_PIN_CTRL, HDA_PIN_IN_ENABLE)) {
        return false;
    }
    return hda_codec_write(controller, codec_id, input_nid, HDA_VERB_SET_AMP_GAIN_MUTE,
                           HDA_AMP_SET_INPUT | HDA_AMP_SET_BOTH | HDA_DEFAULT_GAIN);
}

// Volume is 0 to 100 and maps onto the 7 bit gain field, 0 also sets mute
bool hda_codec_set_volume(hda_controller_t* controller, uint8_t codec_id,
                         uint8_t node_id, uint8_t volume) {
    if (!controller || codec_id >= HDA_MAX_CODECS || !controller->codecs[codec_id].is_present) {
        return false;
    }
    if (volume > 100) volume = 100;
    uint32_t payload = HDA_AMP_SET_OUTPUT | HDA_AMP_SET_BOTH | ((uint32_t)volume * HDA_AMP_GAIN_MASK / 100);
    if (volume == 0) payload |= HDA_AMP_MUTE;
    return hda_codec_write(controller, codec_id, node_id, HDA_VERB_SET_AMP_GAIN_MUTE, payload);
}

bool hda_codec_setup_output_path(hda_controller_t* controller, uint8_t codec_id) {
    hda_codec_t* codec = &controller->codecs[codec_id];
    
    if (codec->num_outputs == 0 || codec->num_pins == 0) {
        terminal_write_string("HDA: No output converter or pin found\n");
        return false;
    }
    
    uint8_t output_nid = codec->output_nodes[0];  // Use first output
    uint8_t pin_nid = codec->pin_nodes[0];        // Use first pin
    
    terminal_write_string("HDA: Setting up path from output ");
    terminal_write_uint(output_nid);
    terminal_write_string(" to pin ");
    terminal_write_uint(pin_nid);
    terminal_write_string("\n");
    
    if (!hda_codec_write(controller, codec_id, pin_nid, HDA_VERB_SET_PIN_CTRL, HDA_PIN_OUT_ENABLE)) {
        return false;
    }
    
    // Set output format (16-bit, 48kHz, stereo)
    uint16_t format = HDA_FMT_PCM | HDA_FMT_16BIT | HDA_FMT_48KHZ | HDA_FMT_STEREO;
    if (!hda_codec_write(controller, codec_id, output_nid, HDA_VERB_SET_STREAM_FORMAT, format)) {
        return false;
    }
    
    uint32_t amp_gain = HDA_AMP_SET_OUTPUT | HDA_AMP_SET_BOTH | HDA_DEFAULT_GAIN;
    if (!hda_codec_write(controller, codec_id, output_nid, HDA_VERB_SET_AMP_GAIN_MUTE, amp_gain)) {
        return false;
    }
    
    if (!hda_codec_write(controller, codec_id, pin_nid, HDA_VERB_SET_AMP_GAIN_MUTE, amp_gain)) {
        return false;
    }
    
    terminal_write_string("HDA: Output path setup complete\n");
    return true;
}

#define HDA_DMA_ALIGN 128
#define HDA_SD_STRIDE 0x20
#define HDA_SD_LPIB 0x04
#define HDA_SD_CBL 0x08
#define HDA_SD_LVI 0x0C
#define HDA_SD_FMT 0x12
#define HDA_SD_BDPL 0x18
#define HDA_SD_BDPU 0x1C
#define HDA_SD_CTL_TAG 0x02
#define HDA_SD_STS 0x03
#define HDA_STREAM_PERIODS 4
#define HDA_RESET_POLLS 1000
#define HDA_BDL_IOC 0x01

static uint16_t sd_base(const hda_stream_t* stream) {
    return HDA_REG_SD0CTL + stream->sd_index * HDA_SD_STRIDE;
}

static void* alloc_dma(uint32_t size, void** raw) {
    *raw = apollo_allocate_memory(size + HDA_DMA_ALIGN);
    if (!*raw) return NULL;
    uintptr_t aligned = ((uintptr_t)*raw + HDA_DMA_ALIGN - 1) & ~(uintptr_t)(HDA_DMA_ALIGN - 1);
    return (void*)aligned;
}

static hda_stream_t* get_stream(hda_controller_t* controller, uint8_t stream_id) {
    if (!controller || stream_id >= HDA_MAX_STREAMS) return NULL;
    return &controller->streams[stream_id];
}

// The spec requires reading SRST back as set before clearing it
static bool reset_stream(hda_controller_t* controller, uint16_t base) {
    hda_write8(controller, base, HDA_SDCTL_SRST);
    uint32_t polls = HDA_RESET_POLLS;
    while (polls-- && !(hda_read8(controller, base) & HDA_SDCTL_SRST)) hda_delay_us(10);
    hda_write8(controller, base, 0);
    polls = HDA_RESET_POLLS;
    while (polls-- && (hda_read8(controller, base) & HDA_SDCTL_SRST)) hda_delay_us(10);
    return (hda_read8(controller, base) & HDA_SDCTL_SRST) == 0;
}

static uint16_t build_format(uint32_t sample_rate, uint8_t channels, uint8_t bits_per_sample) {
    uint16_t format = HDA_FMT_PCM;
    switch (sample_rate) {
        case 8000:   format |= HDA_FMT_8KHZ; break;
        case 11025:  format |= HDA_FMT_11KHZ; break;
        case 16000:  format |= HDA_FMT_16KHZ; break;
        case 22050:  format |= HDA_FMT_22KHZ; break;
        case 32000:  format |= HDA_FMT_32KHZ; break;
        case 44100:  format |= HDA_FMT_44KHZ; break;
        case 88200:  format |= HDA_FMT_88KHZ; break;
        case 96000:  format |= HDA_FMT_96KHZ; break;
        default:     format |= HDA_FMT_48KHZ; break;
    }
    switch (bits_per_sample) {
        case 8:  format |= HDA_FMT_8BIT; break;
        case 20: format |= HDA_FMT_20BIT; break;
        case 24: format |= HDA_FMT_24BIT; break;
        case 32: format |= HDA_FMT_32BIT; break;
        default: format |= HDA_FMT_16BIT; break;
    }
    return format | ((channels - 1) & 0x0F);
}

// Points the first present codec's converter at this stream tag and format
static void bind_converter(hda_controller_t* controller, const hda_stream_t* stream) {
    for (uint8_t cad = 0; cad < HDA_MAX_CODECS; cad++) {
        hda_codec_t* codec = &controller->codecs[cad];
        if (!codec->is_present) continue;
        uint8_t count = stream->is_output ? codec->num_outputs : codec->num_inputs;
        if (count == 0) continue;
        uint8_t node = stream->is_output ? codec->output_nodes[0] : codec->input_nodes[0];
        hda_codec_write(controller, cad, node, HDA_VERB_SET_STREAM_FORMAT, stream->format);
        hda_codec_write(controller, cad, node, HDA_VERB_SET_CONV_CTRL, (uint32_t)stream->stream_tag << 4);
        return;
    }
}

void hda_stream_release(hda_controller_t* controller, uint8_t stream_id) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    if (!stream) return;
    if (stream->is_active) hda_stream_stop(controller, stream_id);
    if (stream->buffer_raw) apollo_free_memory(stream->buffer_raw);
    if (stream->bdl_raw) apollo_free_memory(stream->bdl_raw);
    hda_memset(stream, 0, sizeof(hda_stream_t));
}

bool hda_stream_setup(hda_controller_t* controller, uint8_t stream_id,
                     bool is_output, uint32_t sample_rate, uint8_t channels,
                     uint8_t bits_per_sample, uint32_t buffer_size) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    uint8_t available = is_output ? controller->num_output_streams : controller->num_input_streams;
    if (!stream || stream_id >= available || buffer_size < HDA_STREAM_PERIODS * HDA_DMA_ALIGN) {
        return false;
    }
    hda_stream_release(controller, stream_id);

    stream->stream_id = stream_id;
    stream->stream_tag = stream_id + 1;  // Stream tags start from 1
    stream->is_output = is_output;
    stream->sd_index = is_output ? controller->num_input_streams + stream_id : stream_id;
    stream->sample_rate = sample_rate;
    stream->channels = channels;
    stream->bits_per_sample = bits_per_sample;
    stream->periods = HDA_STREAM_PERIODS;
    stream->period_size = (buffer_size / HDA_STREAM_PERIODS) & ~(uint32_t)(HDA_DMA_ALIGN - 1);
    stream->buffer_size = stream->period_size * HDA_STREAM_PERIODS;
    stream->format = build_format(sample_rate, channels, bits_per_sample);

    stream->buffer = alloc_dma(stream->buffer_size, &stream->buffer_raw);
    stream->bdl_entries = stream->periods;
    stream->bdl = alloc_dma(sizeof(hda_bdl_entry_t) * stream->bdl_entries, &stream->bdl_raw);
    if (!stream->buffer || !stream->bdl) {
        hda_stream_release(controller, stream_id);
        return false;
    }
    stream->buffer_phys = (uintptr_t)stream->buffer;
    stream->bdl_phys = (uintptr_t)stream->bdl;
    hda_memset(stream->buffer, 0, stream->buffer_size);
    for (uint32_t i = 0; i < stream->bdl_entries; i++) {
        stream->bdl[i].address = stream->buffer_phys + (i * stream->period_size);
        stream->bdl[i].length = stream->period_size;
        stream->bdl[i].flags = HDA_BDL_IOC;
    }

    uint16_t base = sd_base(stream);
    if (!reset_stream(controller, base)) {
        hda_stream_release(controller, stream_id);
        return false;
    }
    hda_write32(controller, base + HDA_SD_BDPL, (uint32_t)stream->bdl_phys);
    hda_write32(controller, base + HDA_SD_BDPU, (uint32_t)((uint64_t)stream->bdl_phys >> 32));
    hda_write16(controller, base + HDA_SD_LVI, stream->bdl_entries - 1);
    hda_write32(controller, base + HDA_SD_CBL, stream->buffer_size);
    hda_write16(controller, base + HDA_SD_FMT, stream->format);
    hda_write8(controller, base + HDA_SD_CTL_TAG, (uint8_t)(stream->stream_tag << 4));
    bind_converter(controller, stream);
    return true;
}

bool hda_stream_start(hda_controller_t* controller, uint8_t stream_id) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    if (!stream || !stream->buffer) return false;
    uint16_t base = sd_base(stream);
    hda_write8(controller, base, hda_read8(controller, base) | HDA_SDCTL_RUN);
    stream->is_active = true;
    return true;
}

bool hda_stream_stop(hda_controller_t* controller, uint8_t stream_id) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    if (!stream || !stream->buffer) return false;
    uint16_t base = sd_base(stream);
    hda_write8(controller, base, hda_read8(controller, base) & ~HDA_SDCTL_RUN);
    stream->is_active = false;
    return true;
}

uint32_t hda_stream_get_position(hda_controller_t* controller, uint8_t stream_id) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    if (!stream || !stream->buffer) return 0;
    return hda_read32(controller, sd_base(stream) + HDA_SD_LPIB) % stream->buffer_size;
}

// Counts what DMA consumed since the last call and silences the part it already played
static void service_output(hda_controller_t* controller, hda_stream_t* stream) {
    uint32_t lpib = hda_stream_get_position(controller, stream->stream_id);
    uint32_t moved = (lpib + stream->buffer_size - stream->last_position) % stream->buffer_size;
    for (uint32_t i = 0; i < moved; i++) {
        stream->buffer[(stream->last_position + i) % stream->buffer_size] = 0;
    }
    stream->last_position = lpib;
    stream->bytes_consumed += moved;
    if (stream->bytes_consumed > stream->bytes_queued) {
        stream->underruns++;
        stream->bytes_queued = stream->bytes_consumed;
        stream->position = lpib;
    }
    uint32_t frame_bytes = stream->channels * (stream->bits_per_sample / 8);
    if (frame_bytes) stream->frames_played = stream->bytes_consumed / frame_bytes;
}

uint32_t hda_stream_queued_bytes(hda_controller_t* controller, uint8_t stream_id) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    if (!stream || !stream->buffer || !stream->is_output) return 0;
    service_output(controller, stream);
    return (uint32_t)(stream->bytes_queued - stream->bytes_consumed);
}

uint32_t hda_stream_free_bytes(hda_controller_t* controller, uint8_t stream_id) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    if (!stream || !stream->buffer || !stream->is_output) return 0;
    uint32_t queued = hda_stream_queued_bytes(controller, stream_id);
    uint32_t in_flight = stream->period_size;
    return (queued + in_flight >= stream->buffer_size) ? 0 : stream->buffer_size - in_flight - queued;
}

uint32_t hda_stream_write(hda_controller_t* controller, uint8_t stream_id, const void* data, uint32_t size) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    if (!stream || !data) return 0;
    uint32_t to_write = hda_stream_free_bytes(controller, stream_id);
    if (to_write > size) to_write = size;
    const uint8_t* bytes = (const uint8_t*)data;
    for (uint32_t i = 0; i < to_write; i++) {
        stream->buffer[(stream->position + i) % stream->buffer_size] = bytes[i];
    }
    stream->position = (stream->position + to_write) % stream->buffer_size;
    stream->bytes_queued += to_write;
    return to_write;
}

bool hda_stream_write_data(hda_controller_t* controller, uint8_t stream_id,
                          const void* data, uint32_t size) {
    return hda_stream_write(controller, stream_id, data, size) == size;
}

uint32_t hda_stream_read(hda_controller_t* controller, uint8_t stream_id, void* data, uint32_t size) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    if (!stream || !stream->buffer || stream->is_output || !data) return 0;
    uint32_t lpib = hda_stream_get_position(controller, stream_id);
    uint32_t available = (lpib + stream->buffer_size - stream->position) % stream->buffer_size;
    uint32_t to_read = available < size ? available : size;
    uint8_t* bytes = (uint8_t*)data;
    for (uint32_t i = 0; i < to_read; i++) {
        bytes[i] = stream->buffer[(stream->position + i) % stream->buffer_size];
    }
    stream->position = (stream->position + to_read) % stream->buffer_size;
    stream->bytes_consumed += to_read;
    return to_read;
}

void hda_interrupt_handler(void) {
    if (!g_hda_controller) return;
    
    hda_controller_t* controller = g_hda_controller;
    
    uint32_t intsts = hda_read32(controller, HDA_REG_INTSTS);
    if (intsts == 0) return;
    
    // Global interrupt
    if (intsts & 0x80000000) {
        controller->interrupts_handled++;
        
        uint8_t rirbsts = hda_read8(controller, HDA_REG_RIRBSTS);
        if (rirbsts & 0x01) {
            // Response available
            hda_write8(controller, HDA_REG_RIRBSTS, rirbsts);
        }
        
        for (uint8_t i = 0; i < HDA_MAX_STREAMS; i++) {
            if (intsts & (1 << i)) {
                uint16_t sd_base = HDA_REG_SD0CTL + (i * 0x20);
                uint8_t sd_sts = hda_read8(controller, sd_base + 0x03);
                
                if (sd_sts & 0x04) {  // Buffer completion interrupt
                    controller->stream_interrupts++;
                    
                    hda_write8(controller, sd_base + 0x03, sd_sts);
                }
            }
        }
    }
    
    hda_write32(controller, HDA_REG_INTSTS, intsts);
}

void hda_dump_controller_info(hda_controller_t* controller) {
    if (!controller) return;
    
    terminal_write_string("\n=== HD AUDIO CONTROLLER INFO ===\n");
    terminal_write_string("PCI Location: ");
    terminal_write_uint(controller->bus);
    terminal_write_string(":");
    terminal_write_uint(controller->device);
    terminal_write_string(":");
    terminal_write_uint(controller->function);
    terminal_write_string("\n");
    
    terminal_write_string("Vendor ID: ");
    terminal_write_hex(controller->vendor_id);
    terminal_write_string(", Device ID: ");
    terminal_write_hex(controller->device_id);
    terminal_write_string("\n");
    
    terminal_write_string("MMIO Base: ");
    terminal_write_hex(controller->mmio_phys);
    terminal_write_string("\n");
    
    terminal_write_string("Output Streams: ");
    terminal_write_uint(controller->num_output_streams);
    terminal_write_string(", Input Streams: ");
    terminal_write_uint(controller->num_input_streams);
    terminal_write_string("\n");
    
    terminal_write_string("Codecs: ");
    terminal_write_uint(controller->num_codecs);
    terminal_write_string("\n");
    
    terminal_write_string("Commands Sent: ");
    terminal_write_uint(controller->corb_commands_sent);
    terminal_write_string(", Responses: ");
    terminal_write_uint(controller->rirb_responses_received);
    terminal_write_string("\n");
    
    terminal_write_string("Interrupts: ");
    terminal_write_uint(controller->interrupts_handled);
    terminal_write_string(", Stream Interrupts: ");
    terminal_write_uint(controller->stream_interrupts);
    terminal_write_string("\n");
    terminal_write_string("===============================\n\n");
}

static void dump_node_list(const char* label, const uint8_t* nodes, uint8_t count) {
    terminal_write_string(label);
    for (uint8_t i = 0; i < count; i++) {
        terminal_write_string(" ");
        terminal_write_uint(nodes[i]);
    }
    terminal_write_string("\n");
}

void hda_dump_codec_info(hda_controller_t* controller, uint8_t codec_id) {
    if (!controller || codec_id >= HDA_MAX_CODECS) return;
    hda_codec_t* codec = &controller->codecs[codec_id];
    terminal_write_string("Codec ");
    terminal_write_uint(codec_id);
    if (!codec->is_present) {
        terminal_write_string(": not present\n");
        return;
    }
    terminal_write_string(": vendor ");
    terminal_write_hex(codec->vendor_id);
    terminal_write_string(" device ");
    terminal_write_hex(codec->device_id);
    terminal_write_string(" revision ");
    terminal_write_uint(codec->revision);
    terminal_write_string("\n  Audio function group node: ");
    terminal_write_uint(codec->audio_function_group);
    terminal_write_string("\n");
    dump_node_list("  Output converters:", codec->output_nodes, codec->num_outputs);
    dump_node_list("  Input converters:", codec->input_nodes, codec->num_inputs);
    dump_node_list("  Pin complexes:", codec->pin_nodes, codec->num_pins);
}

void hda_dump_stream_info(hda_controller_t* controller, uint8_t stream_id) {
    hda_stream_t* stream = get_stream(controller, stream_id);
    if (!stream) return;
    terminal_write_string("Stream ");
    terminal_write_uint(stream_id);
    if (!stream->buffer) {
        terminal_write_string(": not set up\n");
        return;
    }
    terminal_write_string(stream->is_output ? ": output" : ": input");
    terminal_write_string(", descriptor ");
    terminal_write_uint(stream->sd_index);
    terminal_write_string(", tag ");
    terminal_write_uint(stream->stream_tag);
    terminal_write_string(stream->is_active ? ", running\n" : ", stopped\n");
    terminal_write_string("  ");
    terminal_write_uint(stream->sample_rate);
    terminal_write_string(" Hz, ");
    terminal_write_uint(stream->channels);
    terminal_write_string(" ch, ");
    terminal_write_uint(stream->bits_per_sample);
    terminal_write_string(" bit, buffer ");
    terminal_write_uint(stream->buffer_size);
    terminal_write_string(" bytes, LPIB ");
    terminal_write_uint(hda_stream_get_position(controller, stream_id));
    uint16_t base = sd_base(stream);
    terminal_write_string("\n  CTL ");
    terminal_write_hex(hda_read32(controller, base) & 0xFFFFFF);
    terminal_write_string(" STS ");
    terminal_write_hex(hda_read8(controller, base + HDA_SD_STS));
    terminal_write_string(" FMT ");
    terminal_write_hex(hda_read16(controller, base + HDA_SD_FMT));
    terminal_write_string(" CBL ");
    terminal_write_uint(hda_read32(controller, base + HDA_SD_CBL));
    terminal_write_string("\n  Frames played: ");
    terminal_write_uint((uint32_t)stream->frames_played);
    terminal_write_string(", underruns: ");
    terminal_write_uint(stream->underruns);
    terminal_write_string("\n");
}
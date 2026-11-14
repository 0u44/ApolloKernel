#include "audio_subsystem.h"
#include "hda_driver.h"
#include "terminal.h"
#include "heap_allocator.h"
#include "time_keeper.h"

// Route memset to the local helper
#ifndef memset
#define memset(dest, val, size) audio_memset(dest, val, size)
#endif

static audio_system_stats_t g_audio_stats = {0};
static bool g_audio_initialized = false;
static uint8_t g_master_volume = 75;
static bool g_master_mute = false;

#define MAX_AUDIO_DEVICES 8
static audio_device_t* g_audio_devices[MAX_AUDIO_DEVICES] = {NULL};
static uint32_t g_next_device_id = 1;

static void audio_memset(void* dest, uint8_t value, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) {
        d[i] = value;
    }
}

static uint32_t audio_format_to_bytes(audio_format_t format) {
    switch (format) {
        case AUDIO_FORMAT_U8: return 1;
        case AUDIO_FORMAT_S16_LE:
        case AUDIO_FORMAT_S16_BE: return 2;
        case AUDIO_FORMAT_S24_LE: return 3;
        case AUDIO_FORMAT_S32_LE:
        case AUDIO_FORMAT_FLOAT_LE: return 4;
        default: return 2;
    }
}

static bool audio_format_is_supported(audio_format_t format) {
    return (format == AUDIO_FORMAT_S16_LE || 
            format == AUDIO_FORMAT_S24_LE || 
            format == AUDIO_FORMAT_S32_LE ||
            format == AUDIO_FORMAT_U8);
}

bool audio_subsystem_initialize(void) {
    terminal_write_string("AUDIO: Initializing audio subsystem...\n");
    
    if (g_audio_initialized) {
        terminal_write_string("AUDIO: Already initialized\n");
        return true;
    }
    
    audio_memset(&g_audio_stats, 0, sizeof(audio_system_stats_t));
    
    for (uint32_t i = 0; i < MAX_AUDIO_DEVICES; i++) {
        g_audio_devices[i] = NULL;
    }
    
    if (!hda_driver_initialize()) {
        terminal_set_color(12, 0);
        terminal_write_string("AUDIO: Failed to initialize HD Audio driver\n");
        terminal_set_color(7, 0);
        return false;
    }
    
    if (g_hda_controller) {
        g_audio_stats.total_devices = g_hda_controller->num_codecs;
        terminal_write_string("AUDIO: Found ");
        terminal_write_uint(g_audio_stats.total_devices);
        terminal_write_string(" audio device(s)\n");
    } else {
        g_audio_stats.total_devices = 0;
        terminal_write_string("AUDIO: No HDA controller available\n");
    }
    
    g_audio_initialized = true;
    
    terminal_set_color(10, 0);
    terminal_write_string("AUDIO: Audio subsystem initialization complete\n");
    terminal_set_color(7, 0);
    
    return true;
}

void audio_subsystem_shutdown(void) {
    if (!g_audio_initialized) return;
    
    terminal_write_string("AUDIO: Shutting down audio subsystem...\n");
    
    for (uint32_t i = 0; i < MAX_AUDIO_DEVICES; i++) {
        if (g_audio_devices[i]) {
            audio_device_close(g_audio_devices[i]);
            g_audio_devices[i] = NULL;
        }
    }
    
    g_audio_initialized = false;
    terminal_write_string("AUDIO: Audio subsystem shutdown complete\n");
}

bool audio_subsystem_self_test(void) {
    if (!g_audio_initialized) {
        terminal_write_string("AUDIO: Subsystem not initialized\n");
        return false;
    }
    
    terminal_write_string("AUDIO: Running self-test...\n");
    
    uint32_t device_count = audio_get_device_count();
    terminal_write_string("AUDIO: Device enumeration - ");
    if (device_count > 0) {
        terminal_set_color(10, 0);
        terminal_write_string("PASSED");
        terminal_set_color(7, 0);
        terminal_write_string(" (");
        terminal_write_uint(device_count);
        terminal_write_string(" devices)\n");
    } else {
        terminal_set_color(12, 0);
        terminal_write_string("FAILED (no devices)\n");
        terminal_set_color(7, 0);
        return false;
    }
    
    if (device_count > 0) {
        audio_device_caps_t caps;
        if (audio_get_device_capabilities(0, &caps)) {
            terminal_write_string("AUDIO: Device capabilities - ");
            terminal_set_color(10, 0);
            terminal_write_string("PASSED\n");
            terminal_set_color(7, 0);
        } else {
            terminal_write_string("AUDIO: Device capabilities - ");
            terminal_set_color(12, 0);
            terminal_write_string("FAILED\n");
            terminal_set_color(7, 0);
        }
    }
    
    uint8_t old_volume = audio_get_master_volume();
    audio_set_master_volume(50);
    if (audio_get_master_volume() == 50) {
        terminal_write_string("AUDIO: Volume control - ");
        terminal_set_color(10, 0);
        terminal_write_string("PASSED\n");
        terminal_set_color(7, 0);
        audio_set_master_volume(old_volume);  // Restore
    } else {
        terminal_write_string("AUDIO: Volume control - ");
        terminal_set_color(12, 0);
        terminal_write_string("FAILED\n");
        terminal_set_color(7, 0);
    }
    
    terminal_write_string("AUDIO: Self-test complete\n");
    return true;
}

uint32_t audio_get_device_count(void) {
    if (!g_audio_initialized || !g_hda_controller) {
        return 0;
    }
    
    return g_hda_controller->num_codecs;
}

bool audio_get_device_info(uint32_t device_id, char* name, uint32_t name_len) {
    if (!g_audio_initialized || !g_hda_controller || 
        device_id >= g_hda_controller->num_codecs || !name || name_len == 0) {
        return false;
    }
    
    hda_codec_t* codec = &g_hda_controller->codecs[device_id];
    if (!codec->is_present) {
        return false;
    }
    
    const char* vendor_name = "Unknown";
    const char* device_name = "Audio Codec";
    
    // Common codec vendors
    if (codec->vendor_id == 0x10EC) vendor_name = "Realtek";
    else if (codec->vendor_id == 0x1106) vendor_name = "VIA";
    else if (codec->vendor_id == 0x11D4) vendor_name = "Analog Devices";
    else if (codec->vendor_id == 0x14F1) vendor_name = "Conexant";
    else if (codec->vendor_id == 0x1013) vendor_name = "Cirrus Logic";
    else if (codec->vendor_id == 0x8384) vendor_name = "SigmaTel";
    else if (codec->vendor_id == 0x434D) vendor_name = "C-Media";
    else if (codec->vendor_id == 0x8086) vendor_name = "Intel";
    
    // No snprintf here, so the name is copied by hand
    uint32_t pos = 0;
    const char* src = vendor_name;
    while (*src && pos < name_len - 1) {
        name[pos++] = *src++;
    }
    if (pos < name_len - 1) name[pos++] = ' ';
    
    src = device_name;
    while (*src && pos < name_len - 1) {
        name[pos++] = *src++;
    }
    name[pos] = '\0';
    
    return true;
}

bool audio_get_device_capabilities(uint32_t device_id, audio_device_caps_t* caps) {
    if (!g_audio_initialized || !g_hda_controller || !caps || 
        device_id >= g_hda_controller->num_codecs) {
        return false;
    }
    
    hda_codec_t* codec = &g_hda_controller->codecs[device_id];
    if (!codec->is_present) {
        return false;
    }
    
    caps->min_rate = 8000;
    caps->max_rate = 96000;
    caps->min_channels = 1;
    caps->max_channels = 8;  // Most codecs support up to 7.1
    
    caps->formats = (1 << AUDIO_FORMAT_U8) |
                    (1 << AUDIO_FORMAT_S16_LE) | 
                    (1 << AUDIO_FORMAT_S24_LE) | 
                    (1 << AUDIO_FORMAT_S32_LE);
    
    caps->buffer_sizes[0] = 64;
    caps->buffer_sizes[1] = 128;
    caps->buffer_sizes[2] = 256;
    caps->buffer_sizes[3] = 512;
    caps->buffer_sizes[4] = 1024;
    caps->buffer_sizes[5] = 2048;
    caps->buffer_sizes[6] = 4096;
    caps->buffer_sizes[7] = 8192;
    caps->num_buffer_sizes = 8;
    
    return true;
}

audio_device_t* audio_device_open(uint32_t device_id, uint8_t device_type) {
    if (!g_audio_initialized || !g_hda_controller || 
        device_id >= g_hda_controller->num_codecs) {
        return NULL;
    }
    
    uint32_t slot = 0;
    for (slot = 0; slot < MAX_AUDIO_DEVICES; slot++) {
        if (g_audio_devices[slot] == NULL) break;
    }
    
    if (slot >= MAX_AUDIO_DEVICES) {
        terminal_write_string("AUDIO: No free device slots\n");
        return NULL;
    }
    
    audio_device_t* device = (audio_device_t*)apollo_allocate_memory(sizeof(audio_device_t));
    if (!device) {
        terminal_write_string("AUDIO: Failed to allocate device structure\n");
        return NULL;
    }
    
    audio_memset(device, 0, sizeof(audio_device_t));
    
    device->device_id = g_next_device_id++;
    device->stream_id = slot;  // Use slot as stream ID
    device->codec_id = device_id;
    device->device_type = device_type;
    device->state = AUDIO_STATE_OPEN;
    device->controller = g_hda_controller;
    device->blocking_mode = true;
    
    device->params.format = AUDIO_FORMAT_S16_LE;
    device->params.rate = 48000;
    device->params.channels = 2;
    device->params.buffer_size = 1024;
    device->params.period_size = 256;
    device->params.periods = 4;
    
    device->frame_size = audio_format_to_bytes(device->params.format) * device->params.channels;
    
    g_audio_devices[slot] = device;
    
    if (device_type & AUDIO_DEVICE_PLAYBACK) {
        g_audio_stats.active_playback++;
    }
    if (device_type & AUDIO_DEVICE_CAPTURE) {
        g_audio_stats.active_capture++;
    }
    
    terminal_write_string("AUDIO: Opened device ");
    terminal_write_uint(device_id);
    terminal_write_string(" as handle ");
    terminal_write_uint(device->device_id);
    terminal_write_string("\n");
    
    return device;
}

bool audio_device_close(audio_device_t* device) {
    if (!device) return false;
    
    if (device->state == AUDIO_STATE_RUNNING) {
        audio_device_stop(device);
    }
    if (device->controller) {
        hda_stream_release(device->controller, device->stream_id);
    }

    for (uint32_t i = 0; i < MAX_AUDIO_DEVICES; i++) {
        if (g_audio_devices[i] == device) {
            g_audio_devices[i] = NULL;
            break;
        }
    }
    
    if (device->device_type & AUDIO_DEVICE_PLAYBACK) {
        if (g_audio_stats.active_playback > 0) {
            g_audio_stats.active_playback--;
        }
    }
    if (device->device_type & AUDIO_DEVICE_CAPTURE) {
        if (g_audio_stats.active_capture > 0) {
            g_audio_stats.active_capture--;
        }
    }
    
    if (device->buffer) {
        apollo_free_memory(device->buffer);
    }
    
    apollo_free_memory(device);
    
    terminal_write_string("AUDIO: Device closed\n");
    return true;
}

bool audio_device_set_params(audio_device_t* device, const audio_params_t* params) {
    if (!device || !params || device->state != AUDIO_STATE_OPEN) {
        return false;
    }
    
    if (!audio_format_is_supported(params->format)) {
        terminal_write_string("AUDIO: Unsupported format\n");
        return false;
    }
    
    if (params->rate < 8000 || params->rate > 192000) {
        terminal_write_string("AUDIO: Invalid sample rate\n");
        return false;
    }
    
    if (params->channels < 1 || params->channels > 8) {
        terminal_write_string("AUDIO: Invalid channel count\n");
        return false;
    }
    
    if (params->buffer_size < 64 || params->buffer_size > 8192) {
        terminal_write_string("AUDIO: Invalid buffer size\n");
        return false;
    }
    
    device->params = *params;
    device->frame_size = audio_format_to_bytes(params->format) * params->channels;
    device->buffer_size_bytes = params->buffer_size * device->frame_size;
    
    terminal_write_string("AUDIO: Parameters set - ");
    terminal_write_uint(params->rate);
    terminal_write_string("Hz, ");
    terminal_write_uint(params->channels);
    terminal_write_string(" channels, buffer=");
    terminal_write_uint(params->buffer_size);
    terminal_write_string(" frames\n");
    
    return true;
}

bool audio_device_get_params(audio_device_t* device, audio_params_t* params) {
    if (!device || !params) {
        return false;
    }
    
    *params = device->params;
    return true;
}

bool audio_device_prepare(audio_device_t* device) {
    if (!device || device->state != AUDIO_STATE_OPEN) {
        return false;
    }
    
    bool is_output = (device->device_type & AUDIO_DEVICE_PLAYBACK) != 0;
    uint8_t bits_per_sample = audio_format_to_bytes(device->params.format) * 8;
    
    if (!hda_stream_setup(device->controller, device->stream_id, is_output,
                         device->params.rate, device->params.channels, 
                         bits_per_sample, device->buffer_size_bytes)) {
        terminal_write_string("AUDIO: Failed to setup HDA stream\n");
        return false;
    }
    
    device->state = AUDIO_STATE_PREPARED;
    terminal_write_string("AUDIO: Device prepared for ");
    terminal_write_string(is_output ? "playback" : "capture");
    terminal_write_string("\n");
    
    return true;
}

bool audio_device_start(audio_device_t* device) {
    if (!device || device->state != AUDIO_STATE_PREPARED) {
        return false;
    }
    
    if (!hda_stream_start(device->controller, device->stream_id)) {
        terminal_write_string("AUDIO: Failed to start HDA stream\n");
        return false;
    }
    
    device->state = AUDIO_STATE_RUNNING;
    terminal_write_string("AUDIO: Device started\n");
    
    return true;
}

bool audio_device_stop(audio_device_t* device) {
    if (!device || device->state != AUDIO_STATE_RUNNING) {
        return false;
    }
    
    if (!hda_stream_stop(device->controller, device->stream_id)) {
        terminal_write_string("AUDIO: Failed to stop HDA stream\n");
        return false;
    }
    
    device->state = AUDIO_STATE_STOPPED;
    terminal_write_string("AUDIO: Device stopped\n");
    
    return true;
}

bool audio_device_pause(audio_device_t* device, bool enable) {
    if (!device) return false;
    
    if (enable && device->state == AUDIO_STATE_RUNNING) {
        // Pause - stop the stream but keep it prepared
        if (hda_stream_stop(device->controller, device->stream_id)) {
            device->state = AUDIO_STATE_PAUSED;
            return true;
        }
    } else if (!enable && device->state == AUDIO_STATE_PAUSED) {
        // Resume - restart the stream
        if (hda_stream_start(device->controller, device->stream_id)) {
            device->state = AUDIO_STATE_RUNNING;
            return true;
        }
    }
    
    return false;
}

bool audio_device_reset(audio_device_t* device) {
    if (!device) return false;
    
    if (device->state == AUDIO_STATE_RUNNING) {
        audio_device_stop(device);
    }
    
    device->position = 0;
    device->hw_position = 0;
    device->frames_total = 0;
    device->xruns = 0;
    
    device->state = AUDIO_STATE_OPEN;
    return true;
}

int32_t audio_device_write(audio_device_t* device, const void* buffer, uint32_t frames) {
    if (!device || !buffer || frames == 0) {
        return AUDIO_ERROR_INVALID;
    }
    
    if (!(device->device_type & AUDIO_DEVICE_PLAYBACK)) {
        return AUDIO_ERROR_INVALID;
    }
    
    if (device->state != AUDIO_STATE_RUNNING) {
        return AUDIO_ERROR_NOT_READY;
    }
    
    uint32_t whole_frames = hda_stream_free_bytes(device->controller, device->stream_id) / device->frame_size;
    if (whole_frames > frames) whole_frames = frames;
    uint32_t bytes = hda_stream_write(device->controller, device->stream_id, buffer, whole_frames * device->frame_size);
    uint32_t written = bytes / device->frame_size;

    device->frames_total += written;
    g_audio_stats.bytes_played += bytes;

    return (int32_t)written;
}

int32_t audio_device_read(audio_device_t* device, void* buffer, uint32_t frames) {
    if (!device || !buffer || frames == 0) {
        return AUDIO_ERROR_INVALID;
    }
    
    if (!(device->device_type & AUDIO_DEVICE_CAPTURE)) {
        return AUDIO_ERROR_INVALID;
    }
    
    if (device->state != AUDIO_STATE_RUNNING) {
        return AUDIO_ERROR_NOT_READY;
    }
    
    uint32_t bytes = hda_stream_read(device->controller, device->stream_id, buffer, frames * device->frame_size);
    uint32_t read = bytes / device->frame_size;

    device->frames_total += read;
    g_audio_stats.bytes_recorded += bytes;

    return (int32_t)read;
}

uint32_t audio_device_available_frames(audio_device_t* device) {
    if (!device || device->state != AUDIO_STATE_RUNNING) {
        return 0;
    }
    
    if (device->device_type & AUDIO_DEVICE_PLAYBACK) {
        return hda_stream_free_bytes(device->controller, device->stream_id) / device->frame_size;
    }
    uint32_t lpib = hda_stream_get_position(device->controller, device->stream_id);
    hda_stream_t* stream = &((hda_controller_t*)device->controller)->streams[device->stream_id];
    if (stream->buffer_size == 0) return 0;
    return ((lpib + stream->buffer_size - stream->position) % stream->buffer_size) / device->frame_size;
}

uint32_t audio_device_delay_frames(audio_device_t* device) {
    if (!device || device->state != AUDIO_STATE_RUNNING) {
        return 0;
    }
    
    return hda_stream_queued_bytes(device->controller, device->stream_id) / device->frame_size;
}

audio_state_t audio_device_get_state(audio_device_t* device) {
    if (!device) {
        return AUDIO_STATE_ERROR;
    }
    return device->state;
}

bool audio_device_wait_ready(audio_device_t* device, uint32_t timeout_ms) {
    if (!device) return false;
    
    uint32_t start_time = get_system_time();
    
    while ((get_system_time() - start_time) < timeout_ms) {
        if (audio_device_available_frames(device) > 0) {
            return true;
        }
        
        time_keeper_delay_us(100);
    }
    
    return false;
}

uint32_t audio_device_get_position(audio_device_t* device) {
    if (!device) return 0;
    
    if (device->state == AUDIO_STATE_RUNNING) {
        device->hw_position = hda_stream_get_position(device->controller, device->stream_id);
    }
    
    return device->hw_position;
}

// Writes the gain or mute bits to every output converter on every codec
static void apply_output_amp(uint32_t gain_or_mute) {
    if (!g_hda_controller) return;
    for (uint8_t codec_id = 0; codec_id < HDA_MAX_CODECS; codec_id++) {
        hda_codec_t* codec = &g_hda_controller->codecs[codec_id];
        if (!codec->is_present) continue;
        for (uint8_t i = 0; i < codec->num_outputs; i++) {
            hda_codec_write(g_hda_controller, codec_id, codec->output_nodes[i], HDA_VERB_SET_AMP_GAIN_MUTE,
                            HDA_AMP_SET_OUTPUT | HDA_AMP_SET_BOTH | gain_or_mute);
        }
    }
}

bool audio_set_master_volume(uint8_t volume) {
    if (volume > 100) volume = 100;
    
    g_master_volume = volume;
    
    if (!g_master_mute) {
        apply_output_amp((volume * HDA_AMP_GAIN_MASK) / 100);
    }
    
    return true;
}

uint8_t audio_get_master_volume(void) {
    return g_master_volume;
}

bool audio_set_mute(bool mute) {
    g_master_mute = mute;
    
    apply_output_amp(mute ? HDA_AMP_MUTE : (g_master_volume * HDA_AMP_GAIN_MASK) / 100);
    return true;
}

bool audio_get_mute(void) {
    return g_master_mute;
}

bool audio_device_set_blocking_mode(audio_device_t* device, bool blocking) {
    if (!device) return false;
    
    device->blocking_mode = blocking;
    return true;
}

bool audio_device_flush(audio_device_t* device) {
    if (!device) return false;
    
    device->position = 0;
    device->hw_position = 0;
    
    return true;
}

bool audio_device_drop(audio_device_t* device) {
    if (!device) return false;
    
    if (device->state == AUDIO_STATE_RUNNING) {
        audio_device_stop(device);
    }
    
    audio_device_flush(device);
    return true;
}

bool audio_get_system_stats(audio_system_stats_t* stats) {
    if (!stats) return false;
    
    *stats = g_audio_stats;
    return true;
}

void audio_dump_system_info(void) {
    terminal_write_string("\n=== AUDIO SUBSYSTEM INFO ===\n");
    terminal_write_string("Initialized: ");
    terminal_write_string(g_audio_initialized ? "YES" : "NO");
    terminal_write_string("\n");
    
    terminal_write_string("Total Devices: ");
    terminal_write_uint(g_audio_stats.total_devices);
    terminal_write_string("\n");
    
    terminal_write_string("Active Playback: ");
    terminal_write_uint(g_audio_stats.active_playback);
    terminal_write_string("\n");
    
    terminal_write_string("Active Capture: ");
    terminal_write_uint(g_audio_stats.active_capture);
    terminal_write_string("\n");
    
    terminal_write_string("Master Volume: ");
    terminal_write_uint(g_master_volume);
    terminal_write_string("%");
    if (g_master_mute) {
        terminal_write_string(" (MUTED)");
    }
    terminal_write_string("\n");
    
    terminal_write_string("Bytes Played: ");
    terminal_write_uint((uint32_t)g_audio_stats.bytes_played);
    terminal_write_string("\n");
    
    terminal_write_string("Bytes Recorded: ");
    terminal_write_uint((uint32_t)g_audio_stats.bytes_recorded);
    terminal_write_string("\n");
    
    terminal_write_string("Total XRUNs: ");
    terminal_write_uint(g_audio_stats.total_xruns);
    terminal_write_string("\n");
    
    if (g_hda_controller) {
        terminal_write_string("\n=== HD AUDIO CONTROLLER ===\n");
        hda_dump_controller_info(g_hda_controller);
    }
    
    terminal_write_string("============================\n\n");
}

const char* audio_get_error_string(int32_t error_code) {
    switch (error_code) {
        case AUDIO_SUCCESS:         return "Success";
        case AUDIO_ERROR_INVALID:   return "Invalid parameter";
        case AUDIO_ERROR_BUSY:      return "Device busy";
        case AUDIO_ERROR_NO_MEMORY: return "Out of memory";
        case AUDIO_ERROR_NO_DEVICE: return "No such device";
        case AUDIO_ERROR_HARDWARE:  return "Hardware error";
        case AUDIO_ERROR_TIMEOUT:   return "Operation timed out";
        case AUDIO_ERROR_UNDERRUN:  return "Buffer underrun";
        case AUDIO_ERROR_OVERRUN:   return "Buffer overrun";
        case AUDIO_ERROR_BAD_PARAMS: return "Invalid parameters";
        case AUDIO_ERROR_NOT_READY: return "Device not ready";
        default:                    return "Unknown error";
    }
}
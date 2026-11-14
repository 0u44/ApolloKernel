#ifndef APOLLO_AUDIO_SUBSYSTEM_H
#define APOLLO_AUDIO_SUBSYSTEM_H

#include "types.h"

struct hda_controller;

#define AUDIO_DEVICE_PLAYBACK   0x01
#define AUDIO_DEVICE_CAPTURE    0x02
#define AUDIO_DEVICE_DUPLEX     (AUDIO_DEVICE_PLAYBACK | AUDIO_DEVICE_CAPTURE)

typedef enum {
    AUDIO_FORMAT_U8 = 0,        // Unsigned 8-bit
    AUDIO_FORMAT_S16_LE,        // Signed 16-bit little endian
    AUDIO_FORMAT_S16_BE,        // Signed 16-bit big endian
    AUDIO_FORMAT_S24_LE,        // Signed 24-bit little endian
    AUDIO_FORMAT_S32_LE,        // Signed 32-bit little endian
    AUDIO_FORMAT_FLOAT_LE,      // 32-bit float little endian
} audio_format_t;

typedef struct {
    uint32_t min_rate;
    uint32_t max_rate;
    uint8_t min_channels;
    uint8_t max_channels;
    uint32_t formats;
    uint32_t buffer_sizes[8];
    uint8_t num_buffer_sizes;
} audio_device_caps_t;

typedef struct {
    audio_format_t format;
    uint32_t rate;              // Sample rate in Hz
    uint8_t channels;
    uint32_t buffer_size;       // Buffer size in frames
    uint32_t period_size;       // Period size in frames
    uint32_t periods;
} audio_params_t;

typedef enum {
    AUDIO_STATE_CLOSED = 0,
    AUDIO_STATE_OPEN,
    AUDIO_STATE_PREPARED,
    AUDIO_STATE_RUNNING,
    AUDIO_STATE_PAUSED,
    AUDIO_STATE_STOPPED,
    AUDIO_STATE_ERROR
} audio_state_t;

typedef struct {
    uint32_t device_id;
    uint8_t stream_id;          // HDA stream ID
    uint8_t codec_id;
    uint8_t device_type;        // PLAYBACK, CAPTURE, or DUPLEX
    audio_state_t state;
    audio_params_t params;
    
    uint8_t* buffer;
    uint32_t buffer_size_bytes; // Buffer size in bytes
    uint32_t frame_size;        // Size of one frame in bytes
    uint32_t position;
    uint32_t hw_position;
    
    uint64_t frames_total;
    uint32_t xruns;             // Number of under/overruns
    
    bool blocking_mode;
    
    struct hda_controller* controller;
} audio_device_t;

typedef struct {
    uint32_t total_devices;
    uint32_t active_playback;
    uint32_t active_capture;
    uint32_t total_xruns;
    uint64_t bytes_played;
    uint64_t bytes_recorded;
} audio_system_stats_t;

bool audio_subsystem_initialize(void);
void audio_subsystem_shutdown(void);
bool audio_subsystem_self_test(void);

uint32_t audio_get_device_count(void);
bool audio_get_device_info(uint32_t device_id, char* name, uint32_t name_len);
bool audio_get_device_capabilities(uint32_t device_id, audio_device_caps_t* caps);

audio_device_t* audio_device_open(uint32_t device_id, uint8_t device_type);
bool audio_device_close(audio_device_t* device);
bool audio_device_set_params(audio_device_t* device, const audio_params_t* params);
bool audio_device_get_params(audio_device_t* device, audio_params_t* params);

bool audio_device_prepare(audio_device_t* device);
bool audio_device_start(audio_device_t* device);
bool audio_device_stop(audio_device_t* device);
bool audio_device_pause(audio_device_t* device, bool enable);
bool audio_device_reset(audio_device_t* device);

int32_t audio_device_write(audio_device_t* device, const void* buffer, uint32_t frames);
int32_t audio_device_read(audio_device_t* device, void* buffer, uint32_t frames);
uint32_t audio_device_available_frames(audio_device_t* device);
uint32_t audio_device_delay_frames(audio_device_t* device);

audio_state_t audio_device_get_state(audio_device_t* device);
bool audio_device_wait_ready(audio_device_t* device, uint32_t timeout_ms);
uint32_t audio_device_get_position(audio_device_t* device);

bool audio_set_master_volume(uint8_t volume);  // 0-100
uint8_t audio_get_master_volume(void);
bool audio_set_mute(bool mute);
bool audio_get_mute(void);

bool audio_device_set_blocking_mode(audio_device_t* device, bool blocking);
bool audio_device_flush(audio_device_t* device);
bool audio_device_drop(audio_device_t* device);

bool audio_get_system_stats(audio_system_stats_t* stats);
void audio_dump_system_info(void);

const char* audio_get_error_string(int32_t error_code);

#define AUDIO_SUCCESS           0
#define AUDIO_ERROR_INVALID     -1
#define AUDIO_ERROR_BUSY        -2
#define AUDIO_ERROR_NO_MEMORY   -3
#define AUDIO_ERROR_NO_DEVICE   -4
#define AUDIO_ERROR_HARDWARE    -5
#define AUDIO_ERROR_TIMEOUT     -6
#define AUDIO_ERROR_UNDERRUN    -7
#define AUDIO_ERROR_OVERRUN     -8
#define AUDIO_ERROR_BAD_PARAMS  -9
#define AUDIO_ERROR_NOT_READY   -10

#endif
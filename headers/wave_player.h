#ifndef APOLLO_WAVE_PLAYER_H
#define APOLLO_WAVE_PLAYER_H

#include "types.h"
#include "audio_subsystem.h"

typedef enum {
    WAV_STATE_IDLE = 0,
    WAV_STATE_LOADING,
    WAV_STATE_READY,
    WAV_STATE_PLAYING,
    WAV_STATE_PAUSED,
    WAV_STATE_STOPPED,
    WAV_STATE_ERROR
} wav_player_state_t;

typedef struct {
    char fmt_header[4];         // "fmt "
    uint32_t fmt_chunk_size;
    uint16_t audio_format;      // Audio format (1 = PCM)
    uint16_t num_channels;
    uint32_t sample_rate;
    uint32_t byte_rate;
    uint16_t block_align;
    uint16_t bits_per_sample;
} __attribute__((packed)) wav_format_t;

typedef struct {
    wav_player_state_t state;
    audio_device_t* audio_device;
    
    char filename[256];
    uint32_t file_size;
    uint8_t* file_data;
    
    wav_format_t format;
    uint32_t data_offset;
    uint32_t data_size;
    
    uint32_t current_position;
    uint32_t total_samples;
    uint32_t samples_played;
    bool loop_enabled;
    
    uint32_t buffer_underruns;
    uint32_t bytes_transferred;
} wav_player_t;

wav_player_t* wav_player_create(void);
void wav_player_destroy(wav_player_t* player);
bool wav_player_load_file(wav_player_t* player, const char* filename);
bool wav_player_play(wav_player_t* player);
bool wav_player_pause(wav_player_t* player);
bool wav_player_stop(wav_player_t* player);
bool wav_player_seek(wav_player_t* player, uint32_t position);
uint32_t wav_player_get_position(wav_player_t* player);
uint32_t wav_player_get_duration(wav_player_t* player);
void wav_player_set_loop(wav_player_t* player, bool loop);
wav_player_state_t wav_player_get_state(wav_player_t* player);
void wav_player_update(wav_player_t* player);  // Called periodically to feed audio
void wav_player_dump_info(wav_player_t* player);
void audio_update_shell_player(void);

wav_player_t* get_shell_player(void);
void set_shell_player(wav_player_t* player);
void clear_shell_player(void);

#endif
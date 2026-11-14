#include "wave_player.h"
#include "filesystem.h"
#include "terminal.h"
#include "heap_allocator.h"
#include "time_keeper.h"

// Route memset to the local helper
#ifndef memset
#define memset(dest, val, size) wav_memset(dest, val, size)
#endif

typedef struct {
    char riff_header[4];        // "RIFF"
    uint32_t file_size;         // File size minus 8
    char wave_header[4];        // "WAVE"
} __attribute__((packed)) wav_header_t;

typedef struct {
    char data_header[4];        // "data"
    uint32_t data_size;
} __attribute__((packed)) wav_data_header_t;

static bool wav_string_compare(const char* s1, const char* s2, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        if (s1[i] != s2[i]) return false;
    }
    return true;
}

static void wav_memcpy(void* dest, const void* src, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < size; i++) {
        d[i] = s[i];
    }
}

static void wav_memset(void* dest, uint8_t value, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) {
        d[i] = value;
    }
}

static uint32_t wav_strlen(const char* str) {
    uint32_t len = 0;
    while (str[len]) len++;
    return len;
}

wav_player_t* wav_player_create(void) {
    wav_player_t* player = (wav_player_t*)apollo_allocate_memory(sizeof(wav_player_t));
    if (!player) {
        terminal_write_string("WAV: Failed to allocate player structure\n");
        return NULL;
    }
    
    wav_memset(player, 0, sizeof(wav_player_t));
    player->state = WAV_STATE_IDLE;
    player->loop_enabled = false;
    
    terminal_write_string("WAV: Player created\n");
    return player;
}

void wav_player_destroy(wav_player_t* player) {
    if (!player) return;
    
    if (player->state == WAV_STATE_PLAYING) {
        wav_player_stop(player);
    }
    
    if (player->audio_device) {
        audio_device_close(player->audio_device);
    }
    
    if (player->file_data) {
        apollo_free_memory(player->file_data);
    }
    
    apollo_free_memory(player);
    terminal_write_string("WAV: Player destroyed\n");
}

bool wav_player_load_file(wav_player_t* player, const char* filename) {
    if (!player || !filename) {
        return false;
    }
    
    player->state = WAV_STATE_LOADING;
    
    uint32_t name_len = wav_strlen(filename);
    if (name_len >= sizeof(player->filename)) {
        name_len = sizeof(player->filename) - 1;
    }
    
    for (uint32_t i = 0; i < name_len; i++) {
        player->filename[i] = filename[i];
    }
    player->filename[name_len] = '\0';
    
    fs_file_handle_t* file_handle = filesystem_open_file(filename, false);
    if (!file_handle) {
        terminal_write_string("WAV: Failed to open file: ");
        terminal_write_string(filename);
        terminal_write_string("\n");
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    fs_file_info_t file_info;
    if (!filesystem_get_file_info(filename, &file_info)) {
        terminal_write_string("WAV: Failed to get file info\n");
        filesystem_close_file(file_handle);
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    player->file_size = file_info.size;
    
    player->file_data = (uint8_t*)apollo_allocate_memory(player->file_size);
    if (!player->file_data) {
        terminal_write_string("WAV: Failed to allocate file buffer (");
        terminal_write_uint(player->file_size);
        terminal_write_string(" bytes)\n");
        filesystem_close_file(file_handle);
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    uint32_t bytes_read = filesystem_read_file(file_handle, player->file_data, player->file_size);
    filesystem_close_file(file_handle);
    
    if (bytes_read != player->file_size) {
        terminal_write_string("WAV: Failed to read complete file (");
        terminal_write_uint(bytes_read);
        terminal_write_string(" of ");
        terminal_write_uint(player->file_size);
        terminal_write_string(" bytes)\n");
        apollo_free_memory(player->file_data);
        player->file_data = NULL;
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    if (player->file_size < sizeof(wav_header_t) + sizeof(wav_format_t) + sizeof(wav_data_header_t)) {
        terminal_write_string("WAV: File too small to be valid WAV (");
        terminal_write_uint(player->file_size);
        terminal_write_string(" bytes)\n");
        apollo_free_memory(player->file_data);
        player->file_data = NULL;
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    wav_header_t* header = (wav_header_t*)player->file_data;
    
    if (!wav_string_compare(header->riff_header, "RIFF", 4) ||
        !wav_string_compare(header->wave_header, "WAVE", 4)) {
        terminal_write_string("WAV: Invalid WAV file header\n");
        apollo_free_memory(player->file_data);
        player->file_data = NULL;
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    uint32_t offset = sizeof(wav_header_t);
    bool found_format = false;
    
    while (offset < player->file_size - 8) {
        char* chunk_id = (char*)(player->file_data + offset);
        uint32_t chunk_size = *(uint32_t*)(player->file_data + offset + 4);
        
        if (wav_string_compare(chunk_id, "fmt ", 4)) {
            if (chunk_size < 16) {  // Minimum PCM format chunk size
                terminal_write_string("WAV: Invalid format chunk size (");
                terminal_write_uint(chunk_size);
                terminal_write_string(")\n");
                apollo_free_memory(player->file_data);
                player->file_data = NULL;
                player->state = WAV_STATE_ERROR;
                return false;
            }
            
            wav_memcpy(&player->format, player->file_data + offset, sizeof(wav_format_t));
            found_format = true;
            break;
        }
        
        offset += 8 + ((chunk_size + 1) & ~1);  // Align to even boundary
    }
    
    if (!found_format) {
        terminal_write_string("WAV: Format chunk not found\n");
        apollo_free_memory(player->file_data);
        player->file_data = NULL;
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    offset = sizeof(wav_header_t);
    bool found_data = false;
    
    while (offset < player->file_size - 8) {
        char* chunk_id = (char*)(player->file_data + offset);
        uint32_t chunk_size = *(uint32_t*)(player->file_data + offset + 4);
        
        if (wav_string_compare(chunk_id, "data", 4)) {
            player->data_offset = offset + 8;
            player->data_size = chunk_size;
            found_data = true;
            break;
        }
        
        offset += 8 + ((chunk_size + 1) & ~1);
    }
    
    if (!found_data) {
        terminal_write_string("WAV: Data chunk not found\n");
        apollo_free_memory(player->file_data);
        player->file_data = NULL;
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    if (player->format.audio_format != 1) {  // Only PCM supported
        terminal_write_string("WAV: Only PCM format supported (found format ");
        terminal_write_uint(player->format.audio_format);
        terminal_write_string(")\n");
        apollo_free_memory(player->file_data);
        player->file_data = NULL;
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    if (player->format.bits_per_sample != 8 && player->format.bits_per_sample != 16 && 
        player->format.bits_per_sample != 24) {
        terminal_write_string("WAV: Only 8-bit, 16-bit, and 24-bit samples supported (found ");
        terminal_write_uint(player->format.bits_per_sample);
        terminal_write_string("-bit)\n");
        apollo_free_memory(player->file_data);
        player->file_data = NULL;
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    if (player->format.num_channels < 1 || player->format.num_channels > 8) {
        terminal_write_string("WAV: Invalid channel count (");
        terminal_write_uint(player->format.num_channels);
        terminal_write_string(")\n");
        apollo_free_memory(player->file_data);
        player->file_data = NULL;
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    if (player->data_offset + player->data_size > player->file_size) {
        terminal_write_string("WAV: Data chunk extends beyond file\n");
        // Adjust data size to fit within file
        player->data_size = player->file_size - player->data_offset;
    }
    
    uint32_t bytes_per_sample = (player->format.bits_per_sample / 8) * player->format.num_channels;
    player->total_samples = player->data_size / bytes_per_sample;
    
    player->state = WAV_STATE_READY;
    
    terminal_write_string("WAV: Loaded ");
    terminal_write_string(filename);
    terminal_write_string("\n");
    terminal_write_string("  Format: ");
    terminal_write_uint(player->format.bits_per_sample);
    terminal_write_string("-bit, ");
    terminal_write_uint(player->format.sample_rate);
    terminal_write_string("Hz, ");
    terminal_write_uint(player->format.num_channels);
    terminal_write_string(" channel(s)\n");
    
    if (player->total_samples > 0) {
        uint32_t duration_sec = player->total_samples / player->format.sample_rate;
        terminal_write_string("  Duration: ");
        terminal_write_uint(duration_sec / 60);
        terminal_write_string(":");
        if ((duration_sec % 60) < 10) terminal_write_string("0");
        terminal_write_uint(duration_sec % 60);
        terminal_write_string("\n");
    }
    
    terminal_write_string("  Data size: ");
    terminal_write_uint(player->data_size);
    terminal_write_string(" bytes, Total samples: ");
    terminal_write_uint(player->total_samples);
    terminal_write_string("\n");
    
    return true;
}

bool wav_player_play(wav_player_t* player) {
    if (!player || player->state != WAV_STATE_READY) {
        return false;
    }
    
    if (!player->audio_device) {
        player->audio_device = audio_device_open(0, AUDIO_DEVICE_PLAYBACK);
        if (!player->audio_device) {
            terminal_write_string("WAV: Failed to open audio device\n");
            player->state = WAV_STATE_ERROR;
            return false;
        }
    }
    
    audio_params_t params;
    
    if (player->format.bits_per_sample == 8) {
        params.format = AUDIO_FORMAT_U8;
    } else if (player->format.bits_per_sample == 16) {
        params.format = AUDIO_FORMAT_S16_LE;
    } else if (player->format.bits_per_sample == 24) {
        params.format = AUDIO_FORMAT_S24_LE;
    } else {
        params.format = AUDIO_FORMAT_S16_LE;
    }
    
    params.rate = player->format.sample_rate;
    params.channels = player->format.num_channels;
    params.buffer_size = 2048;  // 2K frames buffer
    params.period_size = 512;   // 512 frame periods
    params.periods = 4;
    
    if (!audio_device_set_params(player->audio_device, &params)) {
        terminal_write_string("WAV: Failed to set audio parameters\n");
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    if (!audio_device_prepare(player->audio_device)) {
        terminal_write_string("WAV: Failed to prepare audio device\n");
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    if (!audio_device_start(player->audio_device)) {
        terminal_write_string("WAV: Failed to start audio device\n");
        player->state = WAV_STATE_ERROR;
        return false;
    }
    
    player->current_position = 0;
    player->samples_played = 0;
    player->bytes_transferred = 0;
    player->state = WAV_STATE_PLAYING;
    
    terminal_write_string("WAV: Playback started\n");
    return true;
}

bool wav_player_pause(wav_player_t* player) {
    if (!player || player->state != WAV_STATE_PLAYING) {
        return false;
    }
    
    if (player->audio_device) {
        audio_device_pause(player->audio_device, true);
    }
    
    player->state = WAV_STATE_PAUSED;
    terminal_write_string("WAV: Playback paused\n");
    return true;
}

bool wav_player_stop(wav_player_t* player) {
    if (!player) return false;
    
    if (player->audio_device && 
        (player->state == WAV_STATE_PLAYING || player->state == WAV_STATE_PAUSED)) {
        audio_device_stop(player->audio_device);
    }
    
    player->current_position = 0;
    player->samples_played = 0;
    player->state = WAV_STATE_READY;
    
    terminal_write_string("WAV: Playback stopped\n");
    return true;
}

bool wav_player_seek(wav_player_t* player, uint32_t position) {
    if (!player || player->state < WAV_STATE_READY) {
        return false;
    }
    
    uint32_t bytes_per_sample = (player->format.bits_per_sample / 8) * player->format.num_channels;
    uint32_t byte_position = position * bytes_per_sample;
    
    if (byte_position >= player->data_size) {
        player->current_position = player->data_size;
        player->samples_played = player->total_samples;
    } else {
        player->current_position = byte_position;
        player->samples_played = position;
    }
    
    return true;
}

void wav_player_update(wav_player_t* player) {
    if (!player || player->state != WAV_STATE_PLAYING || !player->audio_device) {
        return;
    }
    
    uint32_t available_frames = audio_device_available_frames(player->audio_device);
    if (available_frames == 0) {
        return;  // Audio buffer is full
    }
    
    uint32_t bytes_per_frame = (player->format.bits_per_sample / 8) * player->format.num_channels;
    
    uint32_t bytes_remaining = player->data_size - player->current_position;
    uint32_t frames_remaining = bytes_remaining / bytes_per_frame;
    
    uint32_t max_frames = 512;  // Limit to 512 frames per update
    uint32_t frames_to_write = available_frames;
    if (frames_to_write > frames_remaining) {
        frames_to_write = frames_remaining;
    }
    if (frames_to_write > max_frames) {
        frames_to_write = max_frames;
    }
    
    if (frames_to_write > 0) {
        uint8_t* audio_data = player->file_data + player->data_offset + player->current_position;
        
        int32_t frames_written = audio_device_write(player->audio_device, audio_data, frames_to_write);
        
        if (frames_written > 0) {
            player->current_position += frames_written * bytes_per_frame;
            player->samples_played += frames_written;
            player->bytes_transferred += frames_written * bytes_per_frame;
        } else if (frames_written < 0) {
            terminal_write_string("WAV: Audio write error: ");
            terminal_write_string(audio_get_error_string(frames_written));
            terminal_write_string("\n");
            player->buffer_underruns++;
        }
    }
    
    if (player->current_position >= player->data_size) {
        if (player->loop_enabled) {
            // Restart from beginning
            player->current_position = 0;
            player->samples_played = 0;
            terminal_write_string("WAV: Looping playback\n");
        } else {
            wav_player_stop(player);
            terminal_write_string("WAV: Playback finished\n");
        }
    }
}

uint32_t wav_player_get_position(wav_player_t* player) {
    if (!player) return 0;
    return player->samples_played;
}

uint32_t wav_player_get_duration(wav_player_t* player) {
    if (!player) return 0;
    return player->total_samples;
}

void wav_player_set_loop(wav_player_t* player, bool loop) {
    if (player) {
        player->loop_enabled = loop;
    }
}

wav_player_state_t wav_player_get_state(wav_player_t* player) {
    if (!player) return WAV_STATE_ERROR;
    return player->state;
}

void wav_player_dump_info(wav_player_t* player) {
    if (!player) return;
    
    terminal_write_string("\n=== WAV PLAYER INFO ===\n");
    terminal_write_string("Filename: ");
    terminal_write_string(player->filename);
    terminal_write_string("\n");
    
    terminal_write_string("State: ");
    switch (player->state) {
        case WAV_STATE_IDLE: terminal_write_string("IDLE"); break;
        case WAV_STATE_LOADING: terminal_write_string("LOADING"); break;
        case WAV_STATE_READY: terminal_write_string("READY"); break;
        case WAV_STATE_PLAYING: terminal_write_string("PLAYING"); break;
        case WAV_STATE_PAUSED: terminal_write_string("PAUSED"); break;
        case WAV_STATE_STOPPED: terminal_write_string("STOPPED"); break;
        case WAV_STATE_ERROR: terminal_write_string("ERROR"); break;
        default: terminal_write_string("UNKNOWN"); break;
    }
    terminal_write_string("\n");
    
    if (player->state >= WAV_STATE_READY) {
        terminal_write_string("Format: ");
        terminal_write_uint(player->format.bits_per_sample);
        terminal_write_string("-bit PCM, ");
        terminal_write_uint(player->format.sample_rate);
        terminal_write_string("Hz, ");
        terminal_write_uint(player->format.num_channels);
        terminal_write_string(" channel(s)\n");
        
        terminal_write_string("File Size: ");
        terminal_write_uint(player->file_size);
        terminal_write_string(" bytes\n");
        
        terminal_write_string("Audio Data: ");
        terminal_write_uint(player->data_size);
        terminal_write_string(" bytes (offset ");
        terminal_write_uint(player->data_offset);
        terminal_write_string(")\n");
        
        terminal_write_string("Total Samples: ");
        terminal_write_uint(player->total_samples);
        terminal_write_string("\n");
        
        if (player->format.sample_rate > 0 && player->total_samples > 0) {
            uint32_t duration_sec = player->total_samples / player->format.sample_rate;
            terminal_write_string("Duration: ");
            terminal_write_uint(duration_sec / 60);
            terminal_write_string(":");
            if ((duration_sec % 60) < 10) terminal_write_string("0");
            terminal_write_uint(duration_sec % 60);
            terminal_write_string("\n");
        }
        
        terminal_write_string("Loop: ");
        terminal_write_string(player->loop_enabled ? "YES" : "NO");
        terminal_write_string("\n");
    }
    
    if (player->state == WAV_STATE_PLAYING || player->samples_played > 0) {
        terminal_write_string("Position: ");
        terminal_write_uint(player->samples_played);
        terminal_write_string(" / ");
        terminal_write_uint(player->total_samples);
        terminal_write_string(" samples\n");
        
        if (player->format.sample_rate > 0) {
            uint32_t current_sec = player->samples_played / player->format.sample_rate;
            terminal_write_string("Time Position: ");
            terminal_write_uint(current_sec / 60);
            terminal_write_string(":");
            if ((current_sec % 60) < 10) terminal_write_string("0");
            terminal_write_uint(current_sec % 60);
            terminal_write_string("\n");
        }
        
        terminal_write_string("Bytes Transferred: ");
        terminal_write_uint(player->bytes_transferred);
        terminal_write_string("\n");
        
        terminal_write_string("Buffer Underruns: ");
        terminal_write_uint(player->buffer_underruns);
        terminal_write_string("\n");
        
        if (player->total_samples > 0) {
            uint32_t progress = (player->samples_played * 100) / player->total_samples;
            terminal_write_string("Progress: ");
            terminal_write_uint(progress);
            terminal_write_string("%\n");
        }
    }
    
    if (player->audio_device) {
        terminal_write_string("Audio Device: Handle ");
        terminal_write_uint(player->audio_device->device_id);
        terminal_write_string(", Stream ");
        terminal_write_uint(player->audio_device->stream_id);
        terminal_write_string(", State: ");
        audio_state_t state = audio_device_get_state(player->audio_device);
        switch (state) {
            case AUDIO_STATE_CLOSED: terminal_write_string("CLOSED"); break;
            case AUDIO_STATE_OPEN: terminal_write_string("OPEN"); break;
            case AUDIO_STATE_PREPARED: terminal_write_string("PREPARED"); break;
            case AUDIO_STATE_RUNNING: terminal_write_string("RUNNING"); break;
            case AUDIO_STATE_PAUSED: terminal_write_string("PAUSED"); break;
            case AUDIO_STATE_STOPPED: terminal_write_string("STOPPED"); break;
            case AUDIO_STATE_ERROR: terminal_write_string("ERROR"); break;
            default: terminal_write_string("UNKNOWN"); break;
        }
        terminal_write_string("\n");
    }
    
    terminal_write_string("=======================\n\n");
}

// Player shared by the shell commands
static wav_player_t* g_shell_player = NULL;

void audio_update_shell_player(void) {
    if (g_shell_player) {
        wav_player_update(g_shell_player);
        
        wav_player_state_t state = wav_player_get_state(g_shell_player);
        if (state == WAV_STATE_READY && !g_shell_player->loop_enabled) {
            // Playback finished and not looping
            wav_player_destroy(g_shell_player);
            g_shell_player = NULL;
        }
    }
}

wav_player_t* get_shell_player(void) {
    return g_shell_player;
}

void set_shell_player(wav_player_t* player) {
    if (g_shell_player && g_shell_player != player) {
        wav_player_destroy(g_shell_player);
    }
    g_shell_player = player;
}

void clear_shell_player(void) {
    if (g_shell_player) {
        wav_player_destroy(g_shell_player);
        g_shell_player = NULL;
    }
}
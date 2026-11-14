#include "program.h"
#include "input_manager.h"
#include "terminal.h"

#define INPUT_RING_SIZE 256
#define LINE_MAX 256
#define TAB_WIDTH 8
#define ASCII_LAST 127
#define CHAR_EOF 0x04
#define CHAR_INTERRUPT 0x03
#define KEY_INTERRUPTED (-1)
#define CHAR_ESCAPE 0x1B
#define CHAR_BACKSPACE '\b'
#define CSI_INTRODUCER '['
#define CSI_FINAL_FIRST 0x40
#define CSI_FINAL_LAST 0x7E
#define EXTENDED_PREFIX 0xE0
#define EXIT_INTERRUPTED 130

typedef enum { OUTPUT_TEXT, OUTPUT_ESCAPE, OUTPUT_CSI } output_state_t;

static char ring[INPUT_RING_SIZE];
static uint32_t ring_head;
static uint32_t ring_tail;
static char line[LINE_MAX];
static uint32_t line_length;
static uint32_t line_position;
static bool extended_pending;
static output_state_t output_state;
static bool canonical;
static bool echo;
static bool signals;
static bool interrupted;

void console_reset(void) {
    ring_head = ring_tail = 0;
    line_length = line_position = 0;
    extended_pending = false;
    output_state = OUTPUT_TEXT;
    canonical = true;
    echo = true;
    signals = true;
    interrupted = false;
}

void console_set_mode(bool line_mode, bool echo_input, bool interrupt_signals) {
    canonical = line_mode;
    echo = echo_input;
    signals = interrupt_signals;
}

static void push_key(char c) {
    uint32_t next = (ring_head + 1) % INPUT_RING_SIZE;
    if (next == ring_tail) return;
    ring[ring_head] = c;
    ring_head = next;
}

// With signals on, Ctrl+C stops the program unless it takes the signal itself
static void interrupt_key(void) {
    if (!signals) {
        push_key(CHAR_INTERRUPT);
        return;
    }
    if (!program_signal_interrupt()) program_kill("^C", EXIT_INTERRUPTED);
    interrupted = true;
}

bool console_canonical(void) {
    return canonical;
}

bool console_echo(void) {
    return echo;
}

/* input */

// Called from the timer while the program runs and from reads, so Ctrl+C works either way
void console_poll_keyboard(void) {
    while (input_manager_has_input()) {
        uint8_t scancode = input_manager_read_scancode();
        if (scancode == 0) {
            extended_pending = input_manager_get_last_scancode() == EXTENDED_PREFIX;
            continue;
        }
        char c = input_manager_scancode_to_ascii(scancode);
        if (extended_pending) {
            extended_pending = false;
            continue;
        }
        if (c <= 0 || c > ASCII_LAST) continue;
        if (input_manager_is_ctrl_pressed() && (c | 0x20) == 'c') {
            interrupt_key();
            continue;
        }
        if (input_manager_is_ctrl_pressed() && (c | 0x20) == 'd') c = CHAR_EOF;
        push_key(c);
    }
}

static int next_key(void) {
    interrupted = false;
    while (ring_tail == ring_head) {
        console_poll_keyboard();
        if (interrupted) return KEY_INTERRUPTED;
        __asm__ volatile("pause");
    }
    char c = ring[ring_tail];
    ring_tail = (ring_tail + 1) % INPUT_RING_SIZE;
    return c;
}

uint32_t console_pending(void) {
    console_poll_keyboard();
    return (line_length - line_position) + (ring_head - ring_tail + INPUT_RING_SIZE) % INPUT_RING_SIZE;
}

bool console_input_ready(void) {
    return console_pending() > 0;
}

// Cooked mode like a terminal: echo, backspace edits, Enter finishes the line, Ctrl+D on an empty line is end of file
static int read_line(void) {
    line_length = line_position = 0;
    while (line_length < LINE_MAX) {
        int c = next_key();
        if (c == KEY_INTERRUPTED) {
            line_length = 0;
            return KEY_INTERRUPTED;
        }
        if (c == CHAR_EOF) {
            if (line_length == 0) return 0;
            break;
        }
        if (c == CHAR_BACKSPACE) {
            if (line_length > 0 && echo) terminal_backspace();
            if (line_length > 0) line_length--;
            continue;
        }
        line[line_length++] = (char)c;
        if (echo) terminal_write_char((char)c);
        if (c == '\n') break;
    }
    return 1;
}

// Raw mode hands over what has been typed, waiting only for the first key
static int64_t read_raw(char* buffer, uint64_t length) {
    uint64_t n = 0;
    do {
        int c = next_key();
        if (c == KEY_INTERRUPTED) return n > 0 ? (int64_t)n : KEY_INTERRUPTED;
        if (echo && c >= ' ') terminal_write_char((char)c);
        buffer[n++] = (char)c;
    } while (n < length && ring_tail != ring_head);
    return (int64_t)n;
}

int64_t console_read(char* buffer, uint64_t length) {
    if (length == 0) return 0;
    if (!canonical && line_position >= line_length) return read_raw(buffer, length);
    if (line_position >= line_length) {
        int r = read_line();
        if (r <= 0) return r;
    }
    uint64_t n = 0;
    while (n < length && line_position < line_length) buffer[n++] = line[line_position++];
    return (int64_t)n;
}

/* output */

static void write_tab(void) {
    uint32_t column = terminal_get_column();
    uint32_t spaces = TAB_WIDTH - column % TAB_WIDTH;
    for (uint32_t i = 0; i < spaces; i++) terminal_write_char(' ');
}

// Escape sequences are consumed so they do not print as text, colors and cursor movement are not supported
static void write_byte(char c) {
    if (output_state == OUTPUT_ESCAPE) {
        output_state = c == CSI_INTRODUCER ? OUTPUT_CSI : OUTPUT_TEXT;
        return;
    }
    if (output_state == OUTPUT_CSI) {
        if (c >= CSI_FINAL_FIRST && c <= CSI_FINAL_LAST) output_state = OUTPUT_TEXT;
        return;
    }
    switch (c) {
        case CHAR_ESCAPE: output_state = OUTPUT_ESCAPE; return;
        case '\n': terminal_write_char('\n'); return;
        case '\r': terminal_set_column(0); return;
        case '\t': write_tab(); return;
        case CHAR_BACKSPACE: if (terminal_get_column() > 0) terminal_set_column(terminal_get_column() - 1); return;
        default: break;
    }
    if ((unsigned char)c >= ' ' && (unsigned char)c <= ASCII_LAST) terminal_write_char(c);
}

void console_write(const char* text, uint64_t length) {
    for (uint64_t i = 0; i < length; i++) write_byte(text[i]);
}
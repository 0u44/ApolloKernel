#include "terminal.h"
#include "input_manager.h"
#include "types.h"

#define VGA_MEMORY_BASE 0xB8000
#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define VGA_CONTROL_REGISTER 0x3D4
#define VGA_DATA_REGISTER 0x3D5
#define VGA_INPUT_STATUS 0x3DA
#define VGA_ATTRIBUTE_INDEX 0x3C0
#define VGA_ATTRIBUTE_READ 0x3C1
#define VGA_ATTRIBUTE_PALETTE_ENABLE 0x20
#define VGA_DAC_WRITE_INDEX 0x3C8
#define VGA_DAC_DATA 0x3C9
#define VGA_PALETTE_ENTRIES 16
#define VGA_DAC_SHIFT 2

#define SCROLLBACK_LINES 100
#define TOTAL_LINES (SCROLLBACK_LINES + VGA_HEIGHT)

typedef struct {
    uint8_t character;
    uint8_t attributes;
} vga_cell_t;

typedef struct {
    vga_cell_t lines[TOTAL_LINES][VGA_WIDTH];
    uint32_t current_line;
    uint32_t total_lines;
    uint32_t view_offset;
    uint32_t cursor_x;
    uint32_t cursor_y;
    uint8_t current_color;
    bool in_scrollback;
} terminal_state_t;

static terminal_state_t term = {0};

static inline void outb(uint16_t port, uint8_t data) {
    __asm__ volatile("outb %0, %1" : : "a"(data), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t result;
    __asm__ volatile("inb %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static void update_display(void) {
    vga_cell_t *vga = (vga_cell_t *)VGA_MEMORY_BASE;

    uint32_t start_line;
    if (term.total_lines <= VGA_HEIGHT) {
        start_line = 0;
    } else {
        start_line = (term.current_line + 1 - VGA_HEIGHT - term.view_offset + TOTAL_LINES) % TOTAL_LINES;
    }

    for (uint32_t row = 0; row < VGA_HEIGHT; row++) {
        uint32_t line_idx = (start_line + row) % TOTAL_LINES;
        for (uint32_t col = 0; col < VGA_WIDTH; col++) {
            vga[row * VGA_WIDTH + col] = term.lines[line_idx][col];
        }
    }
}

// Writes one buffer cell to the screen instead of copying the whole view
static void draw_cell(uint32_t col) {
    if (term.in_scrollback || col >= VGA_WIDTH) return;
    vga_cell_t *vga = (vga_cell_t *)VGA_MEMORY_BASE;
    vga[term.cursor_y * VGA_WIDTH + col] = term.lines[term.current_line][col];
}

static void draw_current_row(void) {
    for (uint32_t col = 0; col < VGA_WIDTH; col++) {
        draw_cell(col);
    }
}

static void update_cursor(void) {
    if (term.in_scrollback) {
        outb(VGA_CONTROL_REGISTER, 0x0A);
        outb(VGA_DATA_REGISTER, 0x20);
        return;
    }

    uint16_t pos = term.cursor_y * VGA_WIDTH + term.cursor_x;
    outb(VGA_CONTROL_REGISTER, 0x0F);
    outb(VGA_DATA_REGISTER, pos & 0xFF);
    outb(VGA_CONTROL_REGISTER, 0x0E);
    outb(VGA_DATA_REGISTER, (pos >> 8) & 0xFF);

    outb(VGA_CONTROL_REGISTER, 0x0A);
    outb(VGA_DATA_REGISTER, 13);
    outb(VGA_CONTROL_REGISTER, 0x0B);
    outb(VGA_DATA_REGISTER, 14);
}

static void new_line(void) {
    term.current_line = (term.current_line + 1) % TOTAL_LINES;
    term.total_lines++;

    for (uint32_t i = 0; i < VGA_WIDTH; i++) {
        term.lines[term.current_line][i].character = ' ';
        term.lines[term.current_line][i].attributes = term.current_color;
    }

    if (term.total_lines <= VGA_HEIGHT) {
        term.cursor_y = term.total_lines - 1;
    } else {
        term.cursor_y = VGA_HEIGHT - 1;
    }
    term.cursor_x = 0;

    if (term.in_scrollback) {
        term.in_scrollback = false;
        term.view_offset = 0;
        update_display();
    } else if (term.total_lines > VGA_HEIGHT) {
        update_display();
    } else {
        draw_current_row();
    }
}

void terminal_initialize(void) {
    for (uint32_t line = 0; line < TOTAL_LINES; line++) {
        for (uint32_t col = 0; col < VGA_WIDTH; col++) {
            term.lines[line][col].character = ' ';
            term.lines[line][col].attributes = 0x07;
        }
    }

    term.current_line = 0;
    term.total_lines = 1;
    term.view_offset = 0;
    term.cursor_x = 0;
    term.cursor_y = 0;
    term.current_color = 0x07;
    term.in_scrollback = false;

    update_display();
    update_cursor();
}

void terminal_clear(void) {
    for (uint32_t line = 0; line < TOTAL_LINES; line++) {
        for (uint32_t col = 0; col < VGA_WIDTH; col++) {
            term.lines[line][col].character = ' ';
            term.lines[line][col].attributes = term.current_color;
        }
    }

    term.current_line = 0;
    term.total_lines = 1;
    term.view_offset = 0;
    term.cursor_x = 0;
    term.cursor_y = 0;
    term.in_scrollback = false;

    update_display();
    update_cursor();
}

void terminal_write_char(char c) {
    if (c == '\n') {
        term.cursor_x = 0;
        new_line();
        update_cursor();
        return;
    }

    if (term.cursor_x >= VGA_WIDTH) {
        term.cursor_x = 0;
        new_line();
    }

    term.lines[term.current_line][term.cursor_x].character = c;
    term.lines[term.current_line][term.cursor_x].attributes = term.current_color;
    draw_cell(term.cursor_x);

    term.cursor_x++;
    update_cursor();
}

// Used by full screen programs that manage their own layout
void terminal_draw_cell(uint32_t row, uint32_t col, char c, uint8_t color) {
    if (row >= VGA_HEIGHT || col >= VGA_WIDTH) return;
    vga_cell_t *vga = (vga_cell_t *)VGA_MEMORY_BASE;
    vga[row * VGA_WIDTH + col].character = (uint8_t)c;
    vga[row * VGA_WIDTH + col].attributes = color;
}

void terminal_place_cursor(uint32_t row, uint32_t col) {
    if (row >= VGA_HEIGHT) row = VGA_HEIGHT - 1;
    if (col >= VGA_WIDTH) col = VGA_WIDTH - 1;
    uint16_t pos = row * VGA_WIDTH + col;
    outb(VGA_CONTROL_REGISTER, 0x0F);
    outb(VGA_DATA_REGISTER, pos & 0xFF);
    outb(VGA_CONTROL_REGISTER, 0x0E);
    outb(VGA_DATA_REGISTER, (pos >> 8) & 0xFF);
}

void terminal_write_string(const char* str) {
    while (*str) {
        terminal_write_char(*str);
        str++;
    }
}

void terminal_set_color(uint8_t fg, uint8_t bg) {
    term.current_color = (bg << 4) | (fg & 0x0F);
}

// Text attribute colors go through the attribute controller to a DAC entry, which holds 6 bit RGB
void terminal_set_custom_color(uint8_t index, uint8_t red, uint8_t green, uint8_t blue) {
    if (index >= VGA_PALETTE_ENTRIES) return;
    inb(VGA_INPUT_STATUS);
    outb(VGA_ATTRIBUTE_INDEX, index);
    uint8_t dac_index = inb(VGA_ATTRIBUTE_READ);
    inb(VGA_INPUT_STATUS);
    outb(VGA_ATTRIBUTE_INDEX, VGA_ATTRIBUTE_PALETTE_ENABLE);

    outb(VGA_DAC_WRITE_INDEX, dac_index);
    outb(VGA_DAC_DATA, red >> VGA_DAC_SHIFT);
    outb(VGA_DAC_DATA, green >> VGA_DAC_SHIFT);
    outb(VGA_DAC_DATA, blue >> VGA_DAC_SHIFT);
}

void terminal_enable_cursor(void) {
    update_cursor();
}

void terminal_disable_cursor(void) {
    outb(VGA_CONTROL_REGISTER, 0x0A);
    outb(VGA_DATA_REGISTER, 0x20);
}

void terminal_backspace(void) {
    if (term.cursor_x > 0) {
        term.cursor_x--;
        term.lines[term.current_line][term.cursor_x].character = ' ';
        term.lines[term.current_line][term.cursor_x].attributes = term.current_color;
        draw_cell(term.cursor_x);
        update_cursor();
    }
}

uint32_t terminal_get_column(void) {
    return term.cursor_x;
}

// Moves the cursor along the current line without touching what is drawn there
void terminal_set_column(uint32_t column) {
    term.cursor_x = column < VGA_WIDTH ? column : VGA_WIDTH - 1;
    update_cursor();
}

uint8_t terminal_get_color(void) {
    return term.current_color;
}

void terminal_handle_scroll_input(uint8_t scan_code) {
    uint32_t max_scroll = (term.total_lines > VGA_HEIGHT) ? term.total_lines - VGA_HEIGHT : 0;

    switch (scan_code) {
        case SCANCODE_PAGE_UP:
            if (max_scroll > 0) {
                term.in_scrollback = true;
                if (term.view_offset + 10 <= max_scroll) {
                    term.view_offset += 10;
                } else {
                    term.view_offset = max_scroll;
                }
                update_display();
                update_cursor();
            }
            break;

        case SCANCODE_PAGE_DOWN:
            if (term.in_scrollback) {
                if (term.view_offset >= 10) {
                    term.view_offset -= 10;
                } else {
                    term.view_offset = 0;
                    term.in_scrollback = false;
                }
                update_display();
                update_cursor();
            }
            break;

        case SCANCODE_UP_ARROW:
            if (input_manager_is_ctrl_pressed() && max_scroll > 0) {
                term.in_scrollback = true;
                if (term.view_offset < max_scroll) {
                    term.view_offset++;
                }
                update_display();
                update_cursor();
            }
            break;

        case SCANCODE_DOWN_ARROW:
            if (input_manager_is_ctrl_pressed() && term.in_scrollback) {
                if (term.view_offset > 0) {
                    term.view_offset--;
                } else {
                    term.in_scrollback = false;
                }
                update_display();
                update_cursor();
            }
            break;

        case SCANCODE_HOME:
            if (input_manager_is_ctrl_pressed() && max_scroll > 0) {
                term.in_scrollback = true;
                term.view_offset = max_scroll;
                update_display();
                update_cursor();
            }
            break;

        case SCANCODE_END:
            if (input_manager_is_ctrl_pressed() && term.in_scrollback) {
                term.in_scrollback = false;
                term.view_offset = 0;
                update_display();
                update_cursor();
            }
            break;
    }
}

void terminal_show_scroll_status(void) {
    if (term.in_scrollback) {
        vga_cell_t *vga = (vga_cell_t *)VGA_MEMORY_BASE;
        uint32_t row = VGA_HEIGHT - 1;

        for (uint32_t i = 0; i < VGA_WIDTH; i++) {
            vga[row * VGA_WIDTH + i].character = ' ';
            vga[row * VGA_WIDTH + i].attributes = 0x70; // Black on white
        }

        const char* msg = "[SCROLLBACK] PgUp/PgDn to scroll, Ctrl+End to exit";
        for (uint32_t i = 0; msg[i] && i < VGA_WIDTH; i++) {
            vga[row * VGA_WIDTH + i].character = msg[i];
            vga[row * VGA_WIDTH + i].attributes = 0x70;
        }
    }
}

void terminal_write_uint(uint32_t value) {
    if (value == 0) {
        terminal_write_char('0');
        return;
    }

    char buffer[11];
    int pos = 0;

    while (value > 0) {
        buffer[pos++] = '0' + (value % 10);
        value /= 10;
    }

    for (int i = pos - 1; i >= 0; i--) {
        terminal_write_char(buffer[i]);
    }
}

void terminal_write_int(int32_t value) {
    if (value < 0) {
        terminal_write_char('-');
        terminal_write_uint((uint32_t)(-value));
    } else {
        terminal_write_uint((uint32_t)value);
    }
}

void terminal_write_hex(uintptr_t value) {
    const char hex_digits[] = "0123456789ABCDEF";
    char buffer[17];
    int pos = 0;

    if (value == 0) {
        terminal_write_string("0x0");
        return;
    }

    while (value > 0) {
        buffer[pos++] = hex_digits[value % 16];
        value /= 16;
    }

    terminal_write_string("0x");
    for (int i = pos - 1; i >= 0; i--) {
        terminal_write_char(buffer[i]);
    }
}
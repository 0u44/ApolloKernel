#include "text_editor.h"
#include "terminal.h"
#include "input_manager.h"
#include "filesystem.h"
#include "types.h"

typedef struct {
    char lines[TEXT_EDITOR_MAX_LINES][TEXT_EDITOR_MAX_LINE_LENGTH];
    uint32_t line_count;
    uint32_t cursor_line;
    uint32_t cursor_column;
    uint32_t top_line;
    char filename[TEXT_EDITOR_MAX_FILENAME];
    bool is_active;
    bool has_changes;
    bool insert_mode;
    bool file_loaded;
    bool syntax_highlight;
    bool needs_full_redraw;
    bool line_dirty;
    char search_buffer[TEXT_EDITOR_SEARCH_BUFFER_SIZE];
    char clipboard[TEXT_EDITOR_CLIPBOARD_SIZE];
    bool selection_active;
    uint32_t selection_start_line;
    uint32_t selection_start_col;
    uint32_t selection_end_line;
    uint32_t selection_end_col;
} text_editor_state_t;

static text_editor_state_t editor = {0};

static const char* c_keywords[] = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "int", "long", "register", "return", "short", "signed", "sizeof", "static",
    "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while",
    "inline", "restrict", "_Bool", "_Complex", "_Imaginary",
    "bool", "true", "false", NULL
};

static uint32_t string_length(const char* str) {
    uint32_t len = 0;
    while (str && str[len] != '\0') len++;
    return len;
}

static bool string_equals(const char* a, const char* b) {
    uint32_t i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i]) return false;
        i++;
    }
    return a[i] == b[i];
}

static bool is_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

static bool is_alnum(char c) {
    return is_alpha(c) || is_digit(c);
}

static bool is_c_keyword(const char* word, uint32_t len) {
    if (len == 0 || len >= TEXT_EDITOR_MAX_LINE_LENGTH) return false;
    
    char temp[TEXT_EDITOR_MAX_LINE_LENGTH];
    for (uint32_t i = 0; i < len; i++) {
        temp[i] = word[i];
    }
    temp[len] = '\0';
    
    for (int i = 0; c_keywords[i] != NULL; i++) {
        if (string_equals(temp, c_keywords[i])) {
            return true;
        }
    }
    return false;
}

static bool is_position_in_selection(uint32_t line, uint32_t col) {
    if (!editor.selection_active) return false;
    
    uint32_t start_line = editor.selection_start_line;
    uint32_t start_col = editor.selection_start_col;
    uint32_t end_line = editor.selection_end_line;
    uint32_t end_col = editor.selection_end_col;
    
    if (start_line > end_line || (start_line == end_line && start_col > end_col)) {
        uint32_t temp = start_line;
        start_line = end_line;
        end_line = temp;
        temp = start_col;
        start_col = end_col;
        end_col = temp;
    }
    
    if (line < start_line || line > end_line) return false;
    if (line == start_line && line == end_line) {
        return col >= start_col && col < end_col;
    }
    if (line == start_line) return col >= start_col;
    if (line == end_line) return col < end_col;
    return true;
}

static void clear_selection(void) {
    if (editor.selection_active) {
        editor.needs_full_redraw = true;
    }
    editor.selection_active = false;
}

static void start_selection(void) {
    editor.selection_active = true;
    editor.selection_start_line = editor.cursor_line;
    editor.selection_start_col = editor.cursor_column;
    editor.selection_end_line = editor.cursor_line;
    editor.selection_end_col = editor.cursor_column;
}

static void update_selection_end(void) {
    if (editor.selection_active) {
        editor.selection_end_line = editor.cursor_line;
        editor.selection_end_col = editor.cursor_column;
        editor.needs_full_redraw = true;
    }
}

static void delete_selection(void) {
    if (!editor.selection_active) return;
    
    uint32_t start_line = editor.selection_start_line;
    uint32_t start_col = editor.selection_start_col;
    uint32_t end_line = editor.selection_end_line;
    uint32_t end_col = editor.selection_end_col;
    
    if (start_line > end_line || (start_line == end_line && start_col > end_col)) {
        uint32_t temp = start_line;
        start_line = end_line;
        end_line = temp;
        temp = start_col;
        start_col = end_col;
        end_col = temp;
    }
    
    if (start_line == end_line) {
        uint32_t line_len = string_length(editor.lines[start_line]);
        for (uint32_t i = start_col; i < line_len - (end_col - start_col); i++) {
            editor.lines[start_line][i] = editor.lines[start_line][i + (end_col - start_col)];
        }
        editor.lines[start_line][line_len - (end_col - start_col)] = '\0';
    } else {
        uint32_t end_line_len = string_length(editor.lines[end_line]);
        for (uint32_t i = end_col; i <= end_line_len; i++) {
            if (start_col + (i - end_col) < TEXT_EDITOR_MAX_LINE_LENGTH - 1) {
                editor.lines[start_line][start_col + (i - end_col)] = editor.lines[end_line][i];
            }
        }
        
        for (uint32_t i = start_line + 1; i <= end_line && i < editor.line_count; i++) {
            if (i + (end_line - start_line) < TEXT_EDITOR_MAX_LINES) {
                string_copy(editor.lines[i], editor.lines[i + (end_line - start_line)]);
            }
        }
        
        editor.line_count -= (end_line - start_line);
        if (editor.line_count == 0) {
            editor.line_count = 1;
            editor.lines[0][0] = '\0';
        }
    }
    
    editor.cursor_line = start_line;
    editor.cursor_column = start_col;
    clear_selection();
    editor.has_changes = true;
    editor.needs_full_redraw = true;
}

static void copy_selection_to_clipboard(void) {
    if (!editor.selection_active) return;
    
    uint32_t start_line = editor.selection_start_line;
    uint32_t start_col = editor.selection_start_col;
    uint32_t end_line = editor.selection_end_line;
    uint32_t end_col = editor.selection_end_col;
    
    if (start_line > end_line || (start_line == end_line && start_col > end_col)) {
        uint32_t temp = start_line;
        start_line = end_line;
        end_line = temp;
        temp = start_col;
        start_col = end_col;
        end_col = temp;
    }
    
    uint32_t clip_pos = 0;
    editor.clipboard[0] = '\0';
    
    for (uint32_t line = start_line; line <= end_line && line < editor.line_count; line++) {
        uint32_t col_start = (line == start_line) ? start_col : 0;
        uint32_t col_end = (line == end_line) ? end_col : string_length(editor.lines[line]);
        
        for (uint32_t col = col_start; col < col_end && clip_pos < TEXT_EDITOR_CLIPBOARD_SIZE - 2; col++) {
            editor.clipboard[clip_pos++] = editor.lines[line][col];
        }
        
        if (line < end_line && clip_pos < TEXT_EDITOR_CLIPBOARD_SIZE - 2) {
            editor.clipboard[clip_pos++] = '\n';
        }
    }
    
    editor.clipboard[clip_pos] = '\0';
}

static void paste_from_clipboard(void) {
    if (string_length(editor.clipboard) == 0) return;
    
    if (editor.selection_active) {
        delete_selection();
    }
    
    uint32_t clip_len = string_length(editor.clipboard);
    for (uint32_t i = 0; i < clip_len; i++) {
        if (editor.clipboard[i] == '\n') {
            if (editor.line_count < TEXT_EDITOR_MAX_LINES - 1) {
                for (uint32_t j = editor.line_count; j > editor.cursor_line; j--) {
                    string_copy(editor.lines[j + 1], editor.lines[j]);
                }
                
                string_copy(editor.lines[editor.cursor_line + 1], 
                           &editor.lines[editor.cursor_line][editor.cursor_column]);
                editor.lines[editor.cursor_line][editor.cursor_column] = '\0';
                
                editor.line_count++;
                editor.cursor_line++;
                editor.cursor_column = 0;
            }
        } else {
            if (editor.cursor_column < TEXT_EDITOR_MAX_LINE_LENGTH - 1) {
                uint32_t line_len = string_length(editor.lines[editor.cursor_line]);
                
                for (uint32_t j = line_len; j > editor.cursor_column; j--) {
                    editor.lines[editor.cursor_line][j] = editor.lines[editor.cursor_line][j - 1];
                }
                
                editor.lines[editor.cursor_line][editor.cursor_column] = editor.clipboard[i];
                editor.lines[editor.cursor_line][line_len + 1] = '\0';
                editor.cursor_column++;
            }
        }
    }
    
    editor.has_changes = true;
    editor.needs_full_redraw = true;
}

void memory_set(void* dest, uint8_t value, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    for (uint32_t i = 0; i < size; i++) {
        d[i] = value;
    }
}

static void format_file_size(uint32_t size, char* buffer) {
    if (size < 1024) {
        uint32_t i = 0;
        uint32_t temp = size;
        if (temp == 0) {
            buffer[i++] = '0';
        } else {
            char digits[16];
            uint32_t digit_count = 0;
            while (temp > 0) {
                digits[digit_count++] = '0' + (temp % 10);
                temp /= 10;
            }
            for (int j = digit_count - 1; j >= 0; j--) {
                buffer[i++] = digits[j];
            }
        }
        buffer[i++] = ' ';
        buffer[i++] = 'B';
        buffer[i] = '\0';
    } else {
        uint32_t kb = size / 1024;
        uint32_t i = 0;
        uint32_t temp = kb;
        if (temp == 0) {
            buffer[i++] = '0';
        } else {
            char digits[16];
            uint32_t digit_count = 0;
            while (temp > 0) {
                digits[digit_count++] = '0' + (temp % 10);
                temp /= 10;
            }
            for (int j = digit_count - 1; j >= 0; j--) {
                buffer[i++] = digits[j];
            }
        }
        buffer[i++] = ' ';
        buffer[i++] = 'K';
        buffer[i++] = 'B';
        buffer[i] = '\0';
    }
}

static uint32_t get_file_size(void) {
    if (!editor.file_loaded || string_length(editor.filename) == 0) {
        return 0;
    }
    
    fs_file_info_t info;
    if (filesystem_get_file_info(editor.filename, &info)) {
        return info.size;
    }
    return 0;
}

#define SCREEN_COLS 80
#define TEXT_ROWS 22
#define FIRST_TEXT_ROW 1
#define STATUS_ROW 24
#define GUTTER_WIDTH 5
#define COLOR_NORMAL 0x07
#define COLOR_TITLE 0x1F
#define COLOR_STATUS 0x70
#define COLOR_GUTTER 0x08

static uint32_t draw_row;
static uint32_t draw_col;
static uint8_t draw_color = COLOR_NORMAL;

static void editor_color(uint8_t fg, uint8_t bg) {
    draw_color = (uint8_t)((bg << 4) | (fg & 0x0F));
}

static void editor_put(char c) {
    if (draw_col < SCREEN_COLS) {
        terminal_draw_cell(draw_row, draw_col++, c, draw_color);
    }
}

static void editor_text(const char* text) {
    while (*text) editor_put(*text++);
}

static void editor_number(uint32_t value) {
    char digits[11];
    int count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value > 0);
    while (count > 0) editor_put(digits[--count]);
}

// Pads the rest of the row so stale characters from the last frame are overwritten
static void editor_begin_row(uint32_t row, uint8_t color) {
    draw_row = row;
    draw_col = 0;
    draw_color = color;
}

static void editor_end_row(uint8_t color) {
    draw_color = color;
    while (draw_col < SCREEN_COLS) editor_put(' ');
}

static void draw_line_with_syntax(uint32_t text_line) {
    const char* line = editor.lines[text_line];
    uint32_t len = string_length(line);
    
    bool in_string = false;
    bool in_char = false;
    bool in_line_comment = false;
    bool in_block_comment = false;
    
    for (uint32_t i = 0; i < len; i++) {
        char c = line[i];
        bool is_selected = is_position_in_selection(text_line, i);
        
        if (is_selected && !editor.syntax_highlight) {
            editor_color(0, 7);
            editor_put(c);
            continue;
        }
        
        if (in_line_comment) {
            editor_color(is_selected ? 15 : 2, is_selected ? 1 : 0);
            editor_put(c);
            continue;
        }
        
        if (in_block_comment) {
            editor_color(is_selected ? 15 : 2, is_selected ? 1 : 0);
            editor_put(c);
            if (c == '*' && i + 1 < len && line[i + 1] == '/') {
                editor_put('/');
                i++;
                in_block_comment = false;
            }
            continue;
        }
        
        if (c == '/' && i + 1 < len && line[i + 1] == '/') {
            in_line_comment = true;
            editor_color(is_selected ? 15 : 2, is_selected ? 1 : 0);
            editor_put(c);
            continue;
        }
        
        if (c == '/' && i + 1 < len && line[i + 1] == '*') {
            in_block_comment = true;
            editor_color(is_selected ? 15 : 2, is_selected ? 1 : 0);
            editor_put(c);
            continue;
        }
        
        if (c == '"' && !in_char) {
            in_string = !in_string;
            editor_color(is_selected ? 15 : 6, is_selected ? 1 : 0);
            editor_put(c);
            continue;
        }
        
        if (c == '\'' && !in_string) {
            in_char = !in_char;
            editor_color(is_selected ? 15 : 6, is_selected ? 1 : 0);
            editor_put(c);
            continue;
        }
        
        if (in_string || in_char) {
            editor_color(is_selected ? 15 : 6, is_selected ? 1 : 0);
            editor_put(c);
            continue;
        }
        
        if (editor.syntax_highlight && c == '#') {
            editor_color(is_selected ? 15 : 5, is_selected ? 1 : 0);
            editor_put(c);
            for (uint32_t j = i + 1; j < len; j++) {
                bool sel = is_position_in_selection(text_line, j);
                editor_color(sel ? 15 : 5, sel ? 1 : 0);
                editor_put(line[j]);
            }
            break;
        }
        
        if (editor.syntax_highlight && is_digit(c)) {
            uint32_t num_start = i;
            while (i < len && (is_digit(line[i]) || line[i] == '.' || 
                   line[i] == 'x' || line[i] == 'X' || 
                   (line[i] >= 'a' && line[i] <= 'f') ||
                   (line[i] >= 'A' && line[i] <= 'F'))) {
                i++;
            }
            i--;
            for (uint32_t j = num_start; j <= i; j++) {
                bool sel = is_position_in_selection(text_line, j);
                editor_color(sel ? 15 : 3, sel ? 1 : 0);
                editor_put(line[j]);
            }
            continue;
        }
        
        if (editor.syntax_highlight && is_alpha(c)) {
            uint32_t word_start = i;
            while (i < len && is_alnum(line[i])) {
                i++;
            }
            
            if (is_c_keyword(&line[word_start], i - word_start)) {
                for (uint32_t j = word_start; j < i; j++) {
                    bool sel = is_position_in_selection(text_line, j);
                    editor_color(sel ? 15 : 14, sel ? 1 : 0);
                    editor_put(line[j]);
                }
            } else {
                for (uint32_t j = word_start; j < i; j++) {
                    bool sel = is_position_in_selection(text_line, j);
                    editor_color(sel ? 0 : 7, sel ? 7 : 0);
                    editor_put(line[j]);
                }
            }
            i--;
            continue;
        }
        
        editor_color(is_selected ? 0 : 7, is_selected ? 7 : 0);
        editor_put(c);
    }
}

static void draw_title_row(void) {
    editor_begin_row(0, COLOR_TITLE);
    editor_text("Apollo Text Editor - ");
    editor_text(editor.filename[0] != '\0' ? editor.filename : "Untitled");
    if (editor.has_changes) {
        editor_text(" [Modified]");
    }
    if (editor.file_loaded) {
        char size_str[32];
        format_file_size(get_file_size(), size_str);
        editor_text(" (");
        editor_text(size_str);
        editor_text(")");
    }
    editor_end_row(COLOR_TITLE);
}

static void draw_text_row(uint32_t screen_line) {
    uint32_t text_line = editor.top_line + screen_line;
    editor_begin_row(FIRST_TEXT_ROW + screen_line, COLOR_GUTTER);
    if (text_line < editor.line_count) {
        if (text_line + 1 < 10) editor_put(' ');
        if (text_line + 1 < 100) editor_put(' ');
        editor_number(text_line + 1);
        editor_text(": ");
        draw_color = COLOR_NORMAL;
        draw_line_with_syntax(text_line);
    } else if (text_line == 0 && editor.line_count == 0) {
        editor_text("    [Empty File]");
    }
    editor_end_row(COLOR_NORMAL);
}

static void draw_status_row(void) {
    editor_begin_row(STATUS_ROW, COLOR_STATUS);
    editor_text(" Ln:");
    editor_number(editor.cursor_line + 1);
    editor_text(" Col:");
    editor_number(editor.cursor_column + 1);
    editor_text(editor.insert_mode ? " INS" : " OVR");
    if (editor.syntax_highlight) editor_text(" [C]");
    if (editor.selection_active) editor_text(" [SEL]");
    editor_text(" | F1:Help F2:Save F3:Exit F4:Find F6:Goto F7:Syntax");
    editor_end_row(COLOR_STATUS);
}

// Full redraws happen on scroll or selection changes, typing only repaints its own line
static void draw_editor_screen(void) {
    if (editor.needs_full_redraw) {
        for (uint32_t screen_line = 0; screen_line < TEXT_ROWS; screen_line++) {
            draw_text_row(screen_line);
        }
        editor_begin_row(FIRST_TEXT_ROW + TEXT_ROWS, COLOR_NORMAL);
        editor_end_row(COLOR_NORMAL);
    } else if (editor.line_dirty && editor.cursor_line >= editor.top_line) {
        draw_text_row(editor.cursor_line - editor.top_line);
    }
    draw_title_row();
    draw_status_row();

    uint32_t column = GUTTER_WIDTH + editor.cursor_column;
    terminal_place_cursor(FIRST_TEXT_ROW + editor.cursor_line - editor.top_line, column);

    editor.needs_full_redraw = false;
    editor.line_dirty = false;
}

static void ensure_cursor_visible(void) {
    if (editor.cursor_line < editor.top_line) {
        editor.top_line = editor.cursor_line;
        editor.needs_full_redraw = true;
    }
    
    if (editor.cursor_line >= editor.top_line + 22) {
        editor.top_line = editor.cursor_line - 21;
        editor.needs_full_redraw = true;
    }
}

static void insert_character(char c) {
    if (editor.selection_active) {
        delete_selection();
    }
    
    if (editor.cursor_line >= TEXT_EDITOR_MAX_LINES) return;
    
    if (editor.cursor_line >= editor.line_count) {
        for (uint32_t i = editor.line_count; i <= editor.cursor_line; i++) {
            editor.lines[i][0] = '\0';
        }
        editor.line_count = editor.cursor_line + 1;
    }
    
    uint32_t line_len = string_length(editor.lines[editor.cursor_line]);
    
    if (editor.insert_mode) {
        if (line_len < TEXT_EDITOR_MAX_LINE_LENGTH - 1) {
            for (uint32_t i = line_len; i > editor.cursor_column; i--) {
                editor.lines[editor.cursor_line][i] = editor.lines[editor.cursor_line][i - 1];
            }
            editor.lines[editor.cursor_line][editor.cursor_column] = c;
            editor.lines[editor.cursor_line][line_len + 1] = '\0';
            editor.cursor_column++;
        }
    } else {
        if (editor.cursor_column < TEXT_EDITOR_MAX_LINE_LENGTH - 1) {
            editor.lines[editor.cursor_line][editor.cursor_column] = c;
            if (editor.cursor_column >= line_len) {
                editor.lines[editor.cursor_line][editor.cursor_column + 1] = '\0';
            }
            editor.cursor_column++;
        }
    }

    editor.has_changes = true;
    editor.line_dirty = true;
}

static void delete_character(void) {
    if (editor.selection_active) {
        delete_selection();
        return;
    }
    
    if (editor.cursor_line >= editor.line_count) return;
    
    uint32_t line_len = string_length(editor.lines[editor.cursor_line]);
    
    if (editor.cursor_column < line_len) {
        for (uint32_t i = editor.cursor_column; i < line_len; i++) {
            editor.lines[editor.cursor_line][i] = editor.lines[editor.cursor_line][i + 1];
        }
        editor.has_changes = true;
        editor.line_dirty = true;
    }
}

static void insert_newline(void) {
    if (editor.selection_active) {
        delete_selection();
    }
    
    if (editor.line_count >= TEXT_EDITOR_MAX_LINES - 1) return;
    
    if (editor.cursor_column < string_length(editor.lines[editor.cursor_line])) {
        for (uint32_t i = editor.line_count; i > editor.cursor_line; i--) {
            string_copy(editor.lines[i + 1], editor.lines[i]);
        }
        
        string_copy(editor.lines[editor.cursor_line + 1], 
                   &editor.lines[editor.cursor_line][editor.cursor_column]);
        editor.lines[editor.cursor_line][editor.cursor_column] = '\0';
        
        editor.line_count++;
    } else {
        for (uint32_t i = editor.line_count; i > editor.cursor_line; i--) {
            string_copy(editor.lines[i + 1], editor.lines[i]);
        }
        editor.lines[editor.cursor_line + 1][0] = '\0';
        editor.line_count++;
    }
    
    editor.cursor_line++;
    editor.cursor_column = 0;
    editor.has_changes = true;
    editor.needs_full_redraw = true;
}

static void move_cursor_up(bool extend_selection) {
    if (editor.cursor_line > 0) {
        if (extend_selection && !editor.selection_active) {
            start_selection();
        }
        
        editor.cursor_line--;
        uint32_t line_len = string_length(editor.lines[editor.cursor_line]);
        if (editor.cursor_column > line_len) {
            editor.cursor_column = line_len;
        }
        
        if (extend_selection) {
            update_selection_end();
        } else {
            clear_selection();
        }
    }
}

static void move_cursor_down(bool extend_selection) {
    if (editor.cursor_line < editor.line_count - 1) {
        if (extend_selection && !editor.selection_active) {
            start_selection();
        }
        
        editor.cursor_line++;
        uint32_t line_len = string_length(editor.lines[editor.cursor_line]);
        if (editor.cursor_column > line_len) {
            editor.cursor_column = line_len;
        }
        
        if (extend_selection) {
            update_selection_end();
        } else {
            clear_selection();
        }
    }
}

static void move_cursor_left(bool extend_selection) {
    if (editor.cursor_column > 0) {
        if (extend_selection && !editor.selection_active) {
            start_selection();
        }
        
        editor.cursor_column--;
        
        if (extend_selection) {
            update_selection_end();
        } else {
            clear_selection();
        }
    }
}

static void move_cursor_right(bool extend_selection) {
    uint32_t line_len = string_length(editor.lines[editor.cursor_line]);
    if (editor.cursor_column < line_len && editor.cursor_column < TEXT_EDITOR_MAX_LINE_LENGTH - 1) {
        if (extend_selection && !editor.selection_active) {
            start_selection();
        }
        
        editor.cursor_column++;
        
        if (extend_selection) {
            update_selection_end();
        } else {
            clear_selection();
        }
    }
}

static void find_text(void) {
    terminal_clear();
    terminal_set_color(14, 0);
    terminal_write_string("Find Text\n");
    terminal_write_string("===========\n\n");
    terminal_set_color(7, 0);
    terminal_write_string("Enter search string: ");
    
    uint32_t search_pos = 0;
    editor.search_buffer[0] = '\0';
    
    while (true) {
        while (!input_manager_has_input()) {
            __asm__ volatile("pause");
        }
        
        uint8_t scan = input_manager_read_scancode();
        char ch = input_manager_scancode_to_ascii(scan);
        
        if (ch == '\n' || ch == '\r') {
            break;
        } else if (ch == 27 || scan == SCANCODE_ESCAPE) {
            editor.needs_full_redraw = true;
            return;
        } else if (ch == '\b' && search_pos > 0) {
            search_pos--;
            editor.search_buffer[search_pos] = '\0';
            terminal_backspace();
        } else if (ch >= 32 && ch <= 126 && search_pos < TEXT_EDITOR_SEARCH_BUFFER_SIZE - 1) {
            editor.search_buffer[search_pos++] = ch;
            editor.search_buffer[search_pos] = '\0';
            terminal_write_char(ch);
        }
    }
    
    if (search_pos == 0) {
        editor.needs_full_redraw = true;
        return;
    }
    
    uint32_t start_line = editor.cursor_line;
    uint32_t start_col = editor.cursor_column + 1;
    bool found = false;
    
    for (uint32_t line = start_line; line < editor.line_count && !found; line++) {
        uint32_t col_start = (line == start_line) ? start_col : 0;
        uint32_t line_len = string_length(editor.lines[line]);
        
        for (uint32_t col = col_start; col + search_pos <= line_len; col++) {
            bool match = true;
            for (uint32_t i = 0; i < search_pos; i++) {
                if (editor.lines[line][col + i] != editor.search_buffer[i]) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                editor.cursor_line = line;
                editor.cursor_column = col;
                found = true;
                break;
            }
        }
    }
    
    if (!found) {
        for (uint32_t line = 0; line <= start_line && !found; line++) {
            uint32_t line_len = string_length(editor.lines[line]);
            uint32_t max_col = (line == start_line) ? start_col : line_len;
            
            for (uint32_t col = 0; col + search_pos <= max_col; col++) {
                bool match = true;
                for (uint32_t i = 0; i < search_pos; i++) {
                    if (editor.lines[line][col + i] != editor.search_buffer[i]) {
                        match = false;
                        break;
                    }
                }
                
                if (match) {
                    editor.cursor_line = line;
                    editor.cursor_column = col;
                    found = true;
                    break;
                }
            }
        }
    }
    
    terminal_write_string("\n\n");
    if (found) {
        terminal_set_color(10, 0);
        terminal_write_string("Found at line ");
        terminal_write_uint(editor.cursor_line + 1);
        terminal_write_string(", column ");
        terminal_write_uint(editor.cursor_column + 1);
    } else {
        terminal_set_color(12, 0);
        terminal_write_string("Text not found");
    }
    terminal_set_color(7, 0);
    terminal_write_string("\n\nPress any key...");
    
    while (!input_manager_has_input()) {
        __asm__ volatile("pause");
    }
    input_manager_read_scancode();
    
    ensure_cursor_visible();
    editor.needs_full_redraw = true;
}

static void goto_line(void) {
    terminal_clear();
    terminal_set_color(14, 0);
    terminal_write_string("Go To Line\n");
    terminal_write_string("============\n\n");
    terminal_set_color(7, 0);
    terminal_write_string("Enter line number (1-");
    terminal_write_uint(editor.line_count);
    terminal_write_string("): ");
    
    char line_buffer[10];
    uint32_t buffer_pos = 0;
    line_buffer[0] = '\0';
    
    while (true) {
        while (!input_manager_has_input()) {
            __asm__ volatile("pause");
        }
        
        uint8_t scan = input_manager_read_scancode();
        char ch = input_manager_scancode_to_ascii(scan);
        
        if (ch == '\n' || ch == '\r') {
            break;
        } else if (ch == 27 || scan == SCANCODE_ESCAPE) {
            editor.needs_full_redraw = true;
            return;
        } else if (ch == '\b' && buffer_pos > 0) {
            buffer_pos--;
            line_buffer[buffer_pos] = '\0';
            terminal_backspace();
        } else if (ch >= '0' && ch <= '9' && buffer_pos < 9) {
            line_buffer[buffer_pos++] = ch;
            line_buffer[buffer_pos] = '\0';
            terminal_write_char(ch);
        }
    }
    
    if (buffer_pos == 0) {
        editor.needs_full_redraw = true;
        return;
    }
    
    uint32_t target_line = 0;
    for (uint32_t i = 0; i < buffer_pos; i++) {
        target_line = target_line * 10 + (line_buffer[i] - '0');
    }
    
    if (target_line > 0 && target_line <= editor.line_count) {
        editor.cursor_line = target_line - 1;
        editor.cursor_column = 0;
        ensure_cursor_visible();
    }
    
    editor.needs_full_redraw = true;
}

static void copy_line(void) {
    terminal_clear();
    
    if (editor.cursor_line < editor.line_count) {
        string_copy(editor.clipboard, editor.lines[editor.cursor_line]);
        terminal_set_color(10, 0);
        terminal_write_string("Line copied to clipboard\n");
        terminal_write_string("Line ");
        terminal_write_uint(editor.cursor_line + 1);
        terminal_write_string(": ");
        terminal_write_string(editor.lines[editor.cursor_line]);
    } else {
        terminal_set_color(12, 0);
        terminal_write_string("No line to copy");
    }
    
    terminal_set_color(7, 0);
    terminal_write_string("\n\nPress any key...");
    
    while (!input_manager_has_input()) {
        __asm__ volatile("pause");
    }
    input_manager_read_scancode();
    
    editor.needs_full_redraw = true;
}

static void delete_line(void) {
    if (editor.line_count == 0) return;
    
    terminal_clear();
    
    if (editor.cursor_line < editor.line_count) {
        terminal_set_color(14, 0);
        terminal_write_string("Line deleted: ");
        terminal_write_string(editor.lines[editor.cursor_line]);
        terminal_write_string("\n");
        
        for (uint32_t i = editor.cursor_line; i < editor.line_count - 1; i++) {
            string_copy(editor.lines[i], editor.lines[i + 1]);
        }
        editor.line_count--;
        
        if (editor.line_count == 0) {
            editor.lines[0][0] = '\0';
            editor.line_count = 1;
        }
        
        if (editor.cursor_line >= editor.line_count) {
            editor.cursor_line = editor.line_count - 1;
        }
        
        editor.cursor_column = 0;
        editor.has_changes = true;
    }
    
    terminal_set_color(7, 0);
    terminal_write_string("\nPress any key...");
    
    while (!input_manager_has_input()) {
        __asm__ volatile("pause");
    }
    input_manager_read_scancode();
    
    editor.needs_full_redraw = true;
}

static void show_help(void) {
    while (input_manager_has_input()) {
        input_manager_read_scancode();
    }
    
    terminal_clear();
    terminal_set_color(15, 1);
    terminal_write_string("                  APOLLO TEXT EDITOR - HELP                          ");
    terminal_set_color(7, 0);
    terminal_write_string("\n");
    
    terminal_set_color(14, 0);
    terminal_write_string("NAVIGATION:");
    terminal_set_color(7, 0);
    terminal_write_string(" Arrows, Home, End, PgUp, PgDn | Ctrl+Arrows = Select\n");
    
    terminal_set_color(14, 0);
    terminal_write_string("EDITING:");
    terminal_set_color(7, 0);
    terminal_write_string(" Insert=Mode  Delete  Backspace  Enter  Tab=4spaces  ESC\n");
    
    terminal_set_color(14, 0);
    terminal_write_string("CLIPBOARD:");
    terminal_set_color(7, 0);
    terminal_write_string(" Ctrl+C=Copy  Ctrl+X=Cut  Ctrl+V=Paste  Ctrl+A=SelectAll\n\n");
    
    terminal_set_color(14, 0);
    terminal_write_string("FUNCTION KEYS:\n");
    terminal_set_color(7, 0);
    terminal_write_string("  F1  Help            F2  Save file       F3  Exit editor\n");
    terminal_write_string("  F4  Find text       F6  Go to line     F7  Toggle syntax\n");
    terminal_write_string("  F8  Copy line       F9  Delete line\n\n");
    
    terminal_set_color(14, 0);
    terminal_write_string("SYNTAX HIGHLIGHTING");
    terminal_set_color(7, 0);
    terminal_write_string(" (F7 to toggle):\n  ");
    terminal_set_color(14, 0);
    terminal_write_string("Keywords");
    terminal_set_color(7, 0);
    terminal_write_string(" (if,for,while,int)  ");
    terminal_set_color(2, 0);
    terminal_write_string("Comments");
    terminal_set_color(7, 0);
    terminal_write_string(" (//,/* */)  ");
    terminal_set_color(6, 0);
    terminal_write_string("Strings\n");
    terminal_set_color(7, 0);
    terminal_write_string("  ");
    terminal_set_color(3, 0);
    terminal_write_string("Numbers");
    terminal_set_color(7, 0);
    terminal_write_string(" (123, 0xFF)     ");
    terminal_set_color(5, 0);
    terminal_write_string("Preprocessor");
    terminal_set_color(7, 0);
    terminal_write_string(" (#include, #define)\n\n");
    
    terminal_set_color(14, 0);
    terminal_write_string("SELECTION:");
    terminal_set_color(7, 0);
    terminal_write_string(" Use Ctrl+Arrows to highlight text. Typing replaces.\n");
    terminal_write_string("             Selected text shows in inverse video. [SEL] indicator.\n\n");
    
    terminal_set_color(14, 0);
    terminal_write_string("STATUS BAR:");
    terminal_set_color(7, 0);
    terminal_write_string(" Shows line/column, mode (INS/OVR), [C]=syntax, [SEL]\n\n");
    
    terminal_set_color(14, 0);
    terminal_write_string("TIPS:");
    terminal_set_color(7, 0);
    terminal_write_string(" Ctrl+Home/End selects to line start/end. F4 searches forward.\n");
    terminal_write_string("      Tab inserts 4 spaces for C code indentation.\n\n");
    
    while (input_manager_has_input()) {
        input_manager_read_scancode();
    }
    
    terminal_set_color(0, 3);
    terminal_write_string(" Press any key to return to editing... ");
    terminal_set_color(7, 0);
    
    while (!input_manager_has_input()) {
        __asm__ volatile("pause");
    }
    input_manager_read_scancode();
    
    while (input_manager_has_input()) {
        input_manager_read_scancode();
    }
    
    editor.needs_full_redraw = true;
}

static bool save_file(void) {
    if (string_length(editor.filename) == 0) {
        terminal_clear();
        terminal_set_color(12, 0);
        terminal_write_string("Error: No filename specified.\n");
        terminal_set_color(7, 0);
        terminal_write_string("Press any key...");
        while (!input_manager_has_input()) {
            __asm__ volatile("pause");
        }
        input_manager_read_scancode();
        editor.needs_full_redraw = true;
        return false;
    }
    
    // Recreated so a shorter save does not keep the old tail
    if (filesystem_file_exists(editor.filename)) {
        filesystem_delete_file(editor.filename);
    }
    fs_file_handle_t* handle = filesystem_open_file(editor.filename, true);
    if (!handle) {
        if (!filesystem_create_file(editor.filename)) {
            terminal_clear();
            terminal_set_color(12, 0);
            terminal_write_string("Error: Cannot create file\n");
            terminal_set_color(7, 0);
            terminal_write_string("Press any key...");
            while (!input_manager_has_input()) {
                __asm__ volatile("pause");
            }
            input_manager_read_scancode();
            editor.needs_full_redraw = true;
            return false;
        }
        
        handle = filesystem_open_file(editor.filename, true);
        if (!handle) {
            terminal_clear();
            terminal_set_color(12, 0);
            terminal_write_string("Error: Cannot open file\n");
            terminal_set_color(7, 0);
            terminal_write_string("Press any key...");
            while (!input_manager_has_input()) {
                __asm__ volatile("pause");
            }
            input_manager_read_scancode();
            editor.needs_full_redraw = true;
            return false;
        }
    }
    
    for (uint32_t i = 0; i < editor.line_count; i++) {
        uint32_t line_len = string_length(editor.lines[i]);
        if (line_len > 0) {
            filesystem_write_file(handle, editor.lines[i], line_len);
        }
        if (i < editor.line_count - 1) {
            filesystem_write_file(handle, "\n", 1);
        }
    }
    
    filesystem_close_file(handle);
    
    terminal_clear();
    terminal_set_color(10, 0);
    terminal_write_string("File saved: ");
    terminal_write_string(editor.filename);
    terminal_write_string("\n");
    terminal_set_color(7, 0);
    terminal_write_string("Press any key...");
    
    editor.has_changes = false;
    
    while (!input_manager_has_input()) {
        __asm__ volatile("pause");
    }
    input_manager_read_scancode();
    
    editor.needs_full_redraw = true;
    return true;
}

static void handle_editor_input(uint8_t scan_code) {
    bool ctrl = input_manager_is_ctrl_pressed();
    
    if (scan_code == 0x3B) {
        show_help();
        return;
    } else if (scan_code == 0x3C) {
        save_file();
        return;
    } else if (scan_code == 0x3D) {
        if (editor.has_changes) {
            terminal_clear();
            terminal_set_color(14, 0);
            terminal_write_string("Save changes? (y/n/ESC): ");
            terminal_set_color(7, 0);
            
            while (true) {
                while (!input_manager_has_input()) {
                    __asm__ volatile("pause");
                }
                uint8_t response_scan = input_manager_read_scancode();
                char response = input_manager_scancode_to_ascii(response_scan);
                
                if (response == 'y' || response == 'Y') {
                    if (save_file()) {
                        editor.is_active = false;
                    }
                    return;
                } else if (response == 'n' || response == 'N') {
                    editor.is_active = false;
                    return;
                } else if (response == 27 || response_scan == SCANCODE_ESCAPE) {
                    editor.needs_full_redraw = true;
                    return;
                }
            }
        } else {
            editor.is_active = false;
        }
        return;
    } else if (scan_code == 0x3E) {
        find_text();
        return;
    } else if (scan_code == 0x40) {
        goto_line();
        return;
    } else if (scan_code == 0x41) {
        editor.syntax_highlight = !editor.syntax_highlight;
        
        terminal_clear();
        terminal_set_color(10, 0);
        terminal_write_string("C Syntax Highlighting: ");
        if (editor.syntax_highlight) {
            terminal_write_string("ENABLED");
        } else {
            terminal_write_string("DISABLED");
        }
        terminal_set_color(7, 0);
        terminal_write_string("\n\nPress any key...");
        
        while (!input_manager_has_input()) {
            __asm__ volatile("pause");
        }
        input_manager_read_scancode();
        
        editor.needs_full_redraw = true;
        return;
    } else if (scan_code == 0x42) {
        copy_line();
        return;
    } else if (scan_code == 0x43) {
        delete_line();
        return;
    }
    
    if (scan_code == SCANCODE_UP_ARROW) {
        move_cursor_up(ctrl);
        ensure_cursor_visible();
        return;
    } else if (scan_code == SCANCODE_DOWN_ARROW) {
        move_cursor_down(ctrl);
        ensure_cursor_visible();
        return;
    } else if (scan_code == SCANCODE_LEFT_ARROW) {
        move_cursor_left(ctrl);
        ensure_cursor_visible();
        return;
    } else if (scan_code == SCANCODE_RIGHT_ARROW) {
        move_cursor_right(ctrl);
        ensure_cursor_visible();
        return;
    } else if (scan_code == SCANCODE_HOME) {
        if (ctrl && !editor.selection_active) {
            start_selection();
        }
        editor.cursor_column = 0;
        if (ctrl) {
            update_selection_end();
        } else {
            clear_selection();
        }
        ensure_cursor_visible();
        return;
    } else if (scan_code == SCANCODE_END) {
        if (ctrl && !editor.selection_active) {
            start_selection();
        }
        editor.cursor_column = string_length(editor.lines[editor.cursor_line]);
        if (ctrl) {
            update_selection_end();
        } else {
            clear_selection();
        }
        ensure_cursor_visible();
        return;
    } else if (scan_code == SCANCODE_PAGE_UP) {
        for (int i = 0; i < 10; i++) move_cursor_up(ctrl);
        ensure_cursor_visible();
        return;
    } else if (scan_code == SCANCODE_PAGE_DOWN) {
        for (int i = 0; i < 10; i++) move_cursor_down(ctrl);
        ensure_cursor_visible();
        return;
    } else if (scan_code == SCANCODE_INSERT) {
        editor.insert_mode = !editor.insert_mode;
        return;
    } else if (scan_code == SCANCODE_DELETE) {
        delete_character();
        ensure_cursor_visible();
        return;
    }
    
    if (ctrl) {
        char ascii = input_manager_scancode_to_ascii(scan_code);
        if (ascii == 'c' || ascii == 'C') {
            copy_selection_to_clipboard();
            editor.needs_full_redraw = true;
            return;
        } else if (ascii == 'x' || ascii == 'X') {
            copy_selection_to_clipboard();
            delete_selection();
            return;
        } else if (ascii == 'v' || ascii == 'V') {
            paste_from_clipboard();
            return;
        } else if (ascii == 'a' || ascii == 'A') {
            editor.selection_active = true;
            editor.selection_start_line = 0;
            editor.selection_start_col = 0;
            editor.selection_end_line = editor.line_count - 1;
            editor.selection_end_col = string_length(editor.lines[editor.line_count - 1]);
            editor.needs_full_redraw = true;
            return;
        }
    }
    
    uint8_t ascii = (uint8_t)input_manager_scancode_to_ascii(scan_code);
    
    if (ascii == '\b') {
        if (editor.selection_active) {
            delete_selection();
        } else if (editor.cursor_column > 0) {
            editor.cursor_column--;
            delete_character();
        }
    } else if (ascii == '\n' || ascii == '\r') {
        insert_newline();
    } else if (ascii == '\t') {
        for (int i = 0; i < 4; i++) {
            insert_character(' ');
        }
    } else if (ascii == 27) {
        clear_selection();
    } else if (ascii >= 32 && ascii <= 126) {
        insert_character((char)ascii);
    }
    
    ensure_cursor_visible();
}

void text_editor_initialize(void) {
    editor.line_count = 0;
    editor.cursor_line = 0;
    editor.cursor_column = 0;
    editor.top_line = 0;
    editor.filename[0] = '\0';
    editor.is_active = false;
    editor.has_changes = false;
    editor.insert_mode = true;
    editor.file_loaded = false;
    editor.syntax_highlight = true;
    editor.needs_full_redraw = true;
    editor.search_buffer[0] = '\0';
    editor.clipboard[0] = '\0';
    editor.selection_active = false;
}

void text_editor_run(const char* filename) {
    editor.is_active = true;
    editor.insert_mode = true;
    editor.file_loaded = false;
    editor.needs_full_redraw = true;
    editor.syntax_highlight = true;
    editor.selection_active = false;
    
    if (filename && string_length(filename) > 0) {
        string_copy(editor.filename, filename);
        text_editor_load_file(filename);
    } else {
        text_editor_new_file();
    }
    
    while (editor.is_active) {
        draw_editor_screen();
        
        while (!input_manager_has_input() && editor.is_active) {
            __asm__ volatile("pause");
        }
        
        if (input_manager_has_input()) {
            uint8_t scan_code = input_manager_read_scancode();
            handle_editor_input(scan_code);
        }
    }
    
    terminal_clear();
}

bool text_editor_load_file(const char* filename) {
    if (!filename || string_length(filename) == 0) {
        return false;
    }
    
    if (!filesystem_file_exists(filename)) {
        text_editor_new_file();
        string_copy(editor.filename, filename);
        editor.needs_full_redraw = true;
        return true;
    }
    
    fs_file_handle_t* handle = filesystem_open_file(filename, false);
    if (!handle) {
        return false;
    }
    
    text_editor_new_file();
    
    char buffer[FS_TOOL_BUFFER_SIZE];
    uint32_t bytes_read = filesystem_read_file(handle, buffer, FS_TOOL_BUFFER_SIZE - 1);
    buffer[bytes_read] = '\0';
    
    filesystem_close_file(handle);
    
    uint32_t line_pos = 0;
    uint32_t char_pos = 0;
    
    for (uint32_t i = 0; i < bytes_read && line_pos < TEXT_EDITOR_MAX_LINES; i++) {
        if (buffer[i] == '\n') {
            editor.lines[line_pos][char_pos] = '\0';
            line_pos++;
            char_pos = 0;
        } else if (char_pos < TEXT_EDITOR_MAX_LINE_LENGTH - 1) {
            editor.lines[line_pos][char_pos++] = buffer[i];
        }
    }
    
    if (char_pos > 0 || line_pos == 0) {
        editor.lines[line_pos][char_pos] = '\0';
        line_pos++;
    }
    
    editor.line_count = line_pos;
    editor.has_changes = false;
    editor.file_loaded = true;
    editor.needs_full_redraw = true;
    string_copy(editor.filename, filename);
    
    return true;
}

bool text_editor_save_file(const char* filename) {
    if (filename) {
        string_copy(editor.filename, filename);
    }
    return save_file();
}

void text_editor_new_file(void) {
    for (uint32_t i = 0; i < TEXT_EDITOR_MAX_LINES; i++) {
        editor.lines[i][0] = '\0';
    }
    editor.line_count = 1;
    editor.cursor_line = 0;
    editor.cursor_column = 0;
    editor.top_line = 0;
    editor.has_changes = false;
    editor.file_loaded = false;
    editor.needs_full_redraw = true;
    editor.selection_active = false;
}

bool text_editor_is_active(void) {
    return editor.is_active;
}

bool text_editor_has_unsaved_changes(void) {
    return editor.has_changes;
}
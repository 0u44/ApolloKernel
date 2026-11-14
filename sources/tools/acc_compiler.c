#include "acc_compiler.h"
#include "acc_native.h"
#include "acc_bytecode.h"
#include "filesystem.h"
#include "terminal.h"
#include "string_utils.h"
#include "types.h"

#define MAX_MACROS 64
#define MAX_GLOBALS 256
#define MAX_FUNCTIONS 128
#define MAX_LOCALS 256
#define MAX_FIXUPS 512
#define MAX_LOOP_DEPTH 16
#define MAX_LOOP_JUMPS 32
#define MAX_GLOBAL_SLOTS 4096
#define MAX_LOCAL_SLOTS 1024
#define MAX_ARRAY_LENGTH 4096
#define ERROR_TEXT 256
#define UNRESOLVED 0xFFFFFFFFu

typedef enum { TK_EOF, TK_IDENT, TK_NUMBER, TK_STRING, TK_KEYWORD, TK_PUNCT } tok_kind_t;

typedef struct {
    tok_kind_t kind;
    char text[ACC_TOKEN_TEXT];
    int32_t value;
    uint32_t line;
} token_t;

typedef struct {
    char name[ACC_TOKEN_TEXT];
    token_t replacement;
} macro_t;

typedef struct {
    char name[64];
    uint16_t slot;
    uint16_t length;
    uint32_t depth;
} variable_t;

typedef struct {
    char name[64];
    uint32_t address;
    int32_t params;
} function_t;

typedef struct {
    uint8_t* bytes;
    uint32_t size;
} code_buffer_t;

typedef struct {
    bool in_init;
    uint32_t offset;
    uint32_t function;
} fixup_t;

typedef struct {
    uint32_t breaks[MAX_LOOP_JUMPS];
    uint32_t break_count;
    uint32_t continues[MAX_LOOP_JUMPS];
    uint32_t continue_count;
} loop_t;

typedef enum { LV_NONE, LV_LOCAL, LV_GLOBAL, LV_LOCAL_ELEM, LV_GLOBAL_ELEM } lvalue_kind_t;

typedef struct {
    lvalue_kind_t kind;
    uint16_t slot;
    uint16_t length;
} lvalue_t;

static struct {
    token_t tokens[ACC_MAX_TOKENS];
    uint32_t token_count;
    uint32_t pos;
    macro_t macros[MAX_MACROS];
    uint32_t macro_count;

    uint8_t func_code[ACC_MAX_CODE_SIZE];
    uint8_t init_code[ACC_MAX_CODE_SIZE];
    code_buffer_t funcs;
    code_buffer_t init;
    code_buffer_t* out;
    uint8_t data[ACC_MAX_DATA_SIZE];
    uint32_t data_size;

    variable_t globals[MAX_GLOBALS];
    uint32_t global_count;
    uint32_t global_slots;
    function_t functions[MAX_FUNCTIONS];
    uint32_t function_count;
    fixup_t fixups[MAX_FIXUPS];
    uint32_t fixup_count;
    variable_t locals[MAX_LOCALS];
    uint32_t local_count;
    uint32_t local_slots;
    uint32_t max_local_slots;
    uint32_t depth;
    loop_t loops[MAX_LOOP_DEPTH];
    uint32_t loop_depth;

    uint8_t image[ACC_HEADER_SIZE + 2 * ACC_MAX_CODE_SIZE + ACC_MAX_DATA_SIZE];
    uint32_t image_size;
    char error[ERROR_TEXT];
    bool has_error;
} cc;

static const char* keywords[] = {
    "int", "char", "void", "FILE", "return", "if", "else", "while", "for", "break", "continue", NULL
};

static const char* punctuators[] = {
    "<<=", ">>=", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "++", "--", "+=", "-=", "*=", "/=",
    "%=", "&=", "|=", "^=", "+", "-", "*", "/", "%", "<", ">", "=", "!", "~", "&", "|", "^", "(", ")",
    "{", "}", "[", "]", ";", ",", "?", ":", NULL
};

static const struct { const char* name; acc_builtin_t id; int32_t min_args; int32_t max_args; } builtins[] = {
    {"printf", SYS_PRINTF, 1, -1}, {"putchar", SYS_PUTCHAR, 1, 1}, {"puts", SYS_PUTS, 1, 1},
    {"getchar", SYS_GETCHAR, 0, 0}, {"exit", SYS_EXIT, 1, 1}, {"fopen", SYS_FOPEN, 2, 2},
    {"fclose", SYS_FCLOSE, 1, 1}, {"fprintf", SYS_FPRINTF, 2, -1}, {"fputs", SYS_FPUTS, 2, 2},
    {NULL, SYS_COUNT, 0, 0}
};

/* errors */

static void error_at(uint32_t line, const char* message, const char* detail) {
    if (cc.has_error) return;
    cc.has_error = true;
    char number[12];
    uint32_t n = 0;
    do { number[n++] = (char)('0' + line % 10); line /= 10; } while (line);
    string_copy(cc.error, "line ");
    uint32_t pos = string_length(cc.error);
    while (n > 0) cc.error[pos++] = number[--n];
    cc.error[pos] = '\0';
    string_concat_n(cc.error, ": ", ERROR_TEXT);
    string_concat_n(cc.error, message, ERROR_TEXT);
    if (detail) {
        string_concat_n(cc.error, " '", ERROR_TEXT);
        string_concat_n(cc.error, detail, ERROR_TEXT);
        string_concat_n(cc.error, "'", ERROR_TEXT);
    }
}

static token_t* peek(void) {
    return &cc.tokens[cc.pos];
}

static void error_here(const char* message) {
    error_at(peek()->line, message, peek()->kind == TK_EOF ? "end of file" : peek()->text);
}

/* lexer */

static bool is_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

static bool is_keyword(const char* text) {
    for (int i = 0; keywords[i]; i++) {
        if (string_equals(keywords[i], text)) return true;
    }
    return false;
}

static token_t* new_token(tok_kind_t kind, uint32_t line) {
    if (cc.token_count >= ACC_MAX_TOKENS - 1) {
        error_at(line, "program has too many tokens", NULL);
        return &cc.tokens[ACC_MAX_TOKENS - 1];
    }
    token_t* t = &cc.tokens[cc.token_count++];
    t->kind = kind;
    t->text[0] = '\0';
    t->value = 0;
    t->line = line;
    return t;
}

static char escape_char(char c) {
    switch (c) {
        case 'n': return '\n';
        case 't': return '\t';
        case 'r': return '\r';
        case '0': return '\0';
        default: return c;
    }
}

static const char* lex_number(const char* s, token_t* t) {
    int32_t value = 0;
    const char* start = s;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        for (;; s++) {
            char c = *s;
            int digit = is_digit(c) ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
            if (digit < 0) break;
            value = value * 16 + digit;
        }
    } else {
        while (is_digit(*s)) value = value * 10 + (*s++ - '0');
    }
    t->value = value;
    uint32_t n = 0;
    while (start + n < s && n < ACC_TOKEN_TEXT - 1) {
        t->text[n] = start[n];
        n++;
    }
    t->text[n] = '\0';
    return s;
}

static const char* lex_quoted(const char* s, token_t* t, char quote, uint32_t line) {
    uint32_t n = 0;
    s++;
    while (*s && *s != quote && *s != '\n') {
        char c = *s++;
        if (c == '\\' && *s) c = escape_char(*s++);
        if (n < ACC_TOKEN_TEXT - 1) t->text[n++] = c;
    }
    t->text[n] = '\0';
    if (*s != quote) error_at(line, "unterminated literal", NULL);
    else s++;
    if (quote == '\'') {
        t->kind = TK_NUMBER;
        t->value = (uint8_t)t->text[0];
    }
    return s;
}

static macro_t* find_macro(const char* name) {
    for (uint32_t i = 0; i < cc.macro_count; i++) {
        if (string_equals(cc.macros[i].name, name)) return &cc.macros[i];
    }
    return NULL;
}

static const char* lex_word(const char* s, uint32_t line) {
    char word[ACC_TOKEN_TEXT];
    uint32_t n = 0;
    while (is_alpha(*s) || is_digit(*s)) {
        if (n < ACC_TOKEN_TEXT - 1) word[n++] = *s;
        s++;
    }
    word[n] = '\0';
    macro_t* macro = find_macro(word);
    token_t* t = new_token(TK_IDENT, line);
    if (macro) {
        *t = macro->replacement;
        t->line = line;
    } else {
        string_copy(t->text, word);
        t->kind = is_keyword(word) ? TK_KEYWORD : TK_IDENT;
    }
    return s;
}

static const char* lex_punct(const char* s, uint32_t line) {
    for (int i = 0; punctuators[i]; i++) {
        uint32_t len = string_length(punctuators[i]);
        bool match = true;
        for (uint32_t j = 0; j < len; j++) {
            if (s[j] != punctuators[i][j]) { match = false; break; }
        }
        if (match) {
            token_t* t = new_token(TK_PUNCT, line);
            string_copy(t->text, punctuators[i]);
            return s + len;
        }
    }
    char bad[2] = {*s, '\0'};
    error_at(line, "unexpected character", bad);
    return s + 1;
}

static const char* skip_line(const char* s) {
    while (*s && *s != '\n') s++;
    return s;
}

// Only #include lines and object like #define of one token are understood
static const char* lex_directive(const char* s, uint32_t line) {
    s++;
    while (*s == ' ' || *s == '\t') s++;
    if (s[0] == 'i' && s[1] == 'n' && s[2] == 'c') return skip_line(s);
    if (!(s[0] == 'd' && s[1] == 'e' && s[2] == 'f')) {
        error_at(line, "unsupported preprocessor directive", NULL);
        return skip_line(s);
    }
    s += 6;
    while (*s == ' ' || *s == '\t') s++;
    if (cc.macro_count >= MAX_MACROS || !is_alpha(*s)) {
        error_at(line, "bad #define", NULL);
        return skip_line(s);
    }
    macro_t* m = &cc.macros[cc.macro_count];
    uint32_t n = 0;
    while (is_alpha(*s) || is_digit(*s)) {
        if (n < ACC_TOKEN_TEXT - 1) m->name[n++] = *s;
        s++;
    }
    m->name[n] = '\0';
    while (*s == ' ' || *s == '\t') s++;
    uint32_t before = cc.token_count;
    if (is_digit(*s)) s = lex_number(s, new_token(TK_NUMBER, line));
    else if (*s == '"' || *s == '\'') s = lex_quoted(s, new_token(TK_STRING, line), *s, line);
    else if (*s == '-' && is_digit(s[1])) { s = lex_number(s + 1, new_token(TK_NUMBER, line)); cc.tokens[before].value = -cc.tokens[before].value; }
    else { error_at(line, "#define value must be a number, character or string", NULL); return skip_line(s); }
    m->replacement = cc.tokens[before];
    cc.token_count = before;
    cc.macro_count++;
    return skip_line(s);
}

static void predefine(const char* name, int32_t value) {
    macro_t* m = &cc.macros[cc.macro_count++];
    string_copy(m->name, name);
    m->replacement.kind = TK_NUMBER;
    m->replacement.value = value;
    string_copy(m->replacement.text, name);
    m->replacement.line = 0;
}

static void tokenize(const char* s) {
    uint32_t line = 1;
    predefine("NULL", 0);
    predefine("EOF", -1);
    while (*s && !cc.has_error) {
        if (*s == '\n') { line++; s++; continue; }
        if (*s == ' ' || *s == '\t' || *s == '\r') { s++; continue; }
        if (s[0] == '/' && s[1] == '/') { s = skip_line(s); continue; }
        if (s[0] == '/' && s[1] == '*') {
            s += 2;
            while (*s && !(s[0] == '*' && s[1] == '/')) { if (*s == '\n') line++; s++; }
            if (*s) s += 2;
            continue;
        }
        if (*s == '#') s = lex_directive(s, line);
        else if (is_digit(*s)) s = lex_number(s, new_token(TK_NUMBER, line));
        else if (*s == '"' || *s == '\'') s = lex_quoted(s, new_token(TK_STRING, line), *s, line);
        else if (is_alpha(*s)) s = lex_word(s, line);
        else s = lex_punct(s, line);
    }
    new_token(TK_EOF, line);
}

/* token helpers */

static bool at(const char* text) {
    token_t* t = peek();
    return (t->kind == TK_PUNCT || t->kind == TK_KEYWORD) && string_equals(t->text, text);
}

static bool accept(const char* text) {
    if (!at(text)) return false;
    cc.pos++;
    return true;
}

static void expect(const char* text) {
    if (accept(text)) return;
    char message[32];
    string_copy(message, "expected ");
    string_concat_n(message, text, sizeof(message));
    string_concat_n(message, " before", sizeof(message));
    error_here(message);
}

static bool at_type(void) {
    return at("int") || at("char") || at("void") || at("FILE");
}

static void parse_type(void) {
    if (!at_type()) { error_here("expected a type"); return; }
    cc.pos++;
    while (accept("*")) {}
}

static const char* expect_identifier(void) {
    token_t* t = peek();
    if (t->kind != TK_IDENT) { error_here("expected a name, found"); return ""; }
    cc.pos++;
    return t->text;
}

/* code emission */

static void emit8(uint8_t value) {
    if (cc.out->size >= ACC_MAX_CODE_SIZE) { error_here("program is too large near"); return; }
    cc.out->bytes[cc.out->size++] = value;
}

static void emit16(uint16_t value) {
    emit8((uint8_t)value);
    emit8((uint8_t)(value >> 8));
}

static void emit32(uint32_t value) {
    emit16((uint16_t)value);
    emit16((uint16_t)(value >> 16));
}

static void patch32(code_buffer_t* buffer, uint32_t offset, uint32_t value) {
    for (int i = 0; i < 4; i++) buffer->bytes[offset + i] = (uint8_t)(value >> (8 * i));
}

static uint32_t emit_jump(acc_opcode_t op) {
    emit8(op);
    emit32(0);
    return cc.out->size - 4;
}

static void patch_jump_to(uint32_t operand, uint32_t target) {
    patch32(cc.out, operand, target - (operand + 4));
}

static void patch_jump_here(uint32_t operand) {
    patch_jump_to(operand, cc.out->size);
}

static void emit_jump_back(acc_opcode_t op, uint32_t target) {
    emit8(op);
    emit32(target - (cc.out->size + 4));
}

static uint32_t add_string(const char* text) {
    uint32_t len = string_length(text) + 1;
    if (cc.data_size + len > ACC_MAX_DATA_SIZE) { error_here("too much string data near"); return 0; }
    uint32_t offset = cc.data_size;
    for (uint32_t i = 0; i < len; i++) cc.data[cc.data_size++] = (uint8_t)text[i];
    return offset;
}

/* symbols */

static variable_t* find_local(const char* name) {
    for (int32_t i = (int32_t)cc.local_count - 1; i >= 0; i--) {
        if (string_equals(cc.locals[i].name, name)) return &cc.locals[i];
    }
    return NULL;
}

static variable_t* find_global(const char* name) {
    for (uint32_t i = 0; i < cc.global_count; i++) {
        if (string_equals(cc.globals[i].name, name)) return &cc.globals[i];
    }
    return NULL;
}

static int32_t find_function(const char* name) {
    for (uint32_t i = 0; i < cc.function_count; i++) {
        if (string_equals(cc.functions[i].name, name)) return (int32_t)i;
    }
    return -1;
}

static int32_t declare_function(const char* name, int32_t params) {
    int32_t index = find_function(name);
    if (index >= 0) {
        if (cc.functions[index].params != params) error_here("parameter count differs from earlier declaration near");
        return index;
    }
    if (cc.function_count >= MAX_FUNCTIONS) { error_here("too many functions near"); return 0; }
    function_t* f = &cc.functions[cc.function_count];
    string_copy_n(f->name, name, sizeof(f->name));
    f->address = UNRESOLVED;
    f->params = params;
    return (int32_t)cc.function_count++;
}

static uint16_t declare_local(const char* name, uint16_t length) {
    uint32_t slots = length ? length : 1;
    if (cc.local_count >= MAX_LOCALS || cc.local_slots + slots > MAX_LOCAL_SLOTS) {
        error_here("too many local variables near");
        return 0;
    }
    variable_t* v = &cc.locals[cc.local_count++];
    string_copy_n(v->name, name, sizeof(v->name));
    v->slot = (uint16_t)cc.local_slots;
    v->length = length;
    v->depth = cc.depth;
    cc.local_slots += slots;
    if (cc.local_slots > cc.max_local_slots) cc.max_local_slots = cc.local_slots;
    return v->slot;
}

static uint16_t declare_global(const char* name, uint16_t length) {
    uint32_t slots = length ? length : 1;
    if (find_global(name) || find_function(name) >= 0) { error_here("name already declared:"); return 0; }
    if (cc.global_count >= MAX_GLOBALS || cc.global_slots + slots > MAX_GLOBAL_SLOTS) {
        error_here("too many globals near");
        return 0;
    }
    variable_t* v = &cc.globals[cc.global_count++];
    string_copy_n(v->name, name, sizeof(v->name));
    v->slot = (uint16_t)cc.global_slots;
    v->length = length;
    cc.global_slots += slots;
    return v->slot;
}

/* expressions */

static void expression(void);
static lvalue_t unary(void);

static void load(lvalue_t lv) {
    switch (lv.kind) {
        case LV_LOCAL: emit8(OP_LDL); emit16(lv.slot); break;
        case LV_GLOBAL: emit8(OP_LDG); emit16(lv.slot); break;
        case LV_LOCAL_ELEM: emit8(OP_LDLI); emit16(lv.slot); emit16(lv.length); break;
        case LV_GLOBAL_ELEM: emit8(OP_LDGI); emit16(lv.slot); emit16(lv.length); break;
        case LV_NONE: break;
    }
}

static void store(lvalue_t lv) {
    switch (lv.kind) {
        case LV_LOCAL: emit8(OP_STL); emit16(lv.slot); break;
        case LV_GLOBAL: emit8(OP_STG); emit16(lv.slot); break;
        case LV_LOCAL_ELEM: emit8(OP_STLI); emit16(lv.slot); emit16(lv.length); break;
        case LV_GLOBAL_ELEM: emit8(OP_STGI); emit16(lv.slot); emit16(lv.length); break;
        case LV_NONE: error_here("cannot assign to this expression near"); break;
    }
}

static void adjust(lvalue_t lv, int8_t delta, bool post) {
    static const uint8_t ops[] = {0, OP_ADJL, OP_ADJG, OP_ADJLI, OP_ADJGI};
    if (lv.kind == LV_NONE) { error_here("++ and -- need a variable near"); return; }
    emit8(ops[lv.kind]);
    emit16(lv.slot);
    if (lv.kind == LV_LOCAL_ELEM || lv.kind == LV_GLOBAL_ELEM) emit16(lv.length);
    emit8((uint8_t)delta);
    emit8(post ? 1 : 0);
}

static int32_t builtin_index(const char* name) {
    for (int32_t i = 0; builtins[i].name; i++) {
        if (string_equals(builtins[i].name, name)) return i;
    }
    return -1;
}

static uint32_t call_arguments(void) {
    uint32_t count = 0;
    expect("(");
    if (!at(")")) {
        do {
            expression();
            count++;
        } while (accept(",") && !cc.has_error);
    }
    expect(")");
    return count;
}

static void call(const char* name) {
    int32_t builtin = builtin_index(name);
    uint32_t argc = call_arguments();
    if (builtin >= 0) {
        if ((int32_t)argc < builtins[builtin].min_args ||
            (builtins[builtin].max_args >= 0 && (int32_t)argc > builtins[builtin].max_args)) {
            error_at(peek()->line, "wrong number of arguments to", name);
        }
        emit8(OP_SYS);
        emit8((uint8_t)builtins[builtin].id);
        emit8((uint8_t)argc);
        return;
    }
    int32_t index = find_function(name);
    if (index < 0) index = declare_function(name, (int32_t)argc);
    if (cc.functions[index].params != (int32_t)argc) error_at(peek()->line, "wrong number of arguments to", name);
    if (cc.fixup_count >= MAX_FIXUPS) { error_here("too many calls near"); return; }
    emit8(OP_CALL);
    cc.fixups[cc.fixup_count++] = (fixup_t){cc.out == &cc.init, cc.out->size, (uint32_t)index};
    emit32(0);
    emit8((uint8_t)argc);
}

static lvalue_t variable(const char* name) {
    variable_t* v = find_local(name);
    bool local = v != NULL;
    if (!v) v = find_global(name);
    if (!v) { error_at(peek()->line, "undeclared identifier", name); return (lvalue_t){LV_NONE, 0, 0}; }
    if (v->length == 0) return (lvalue_t){local ? LV_LOCAL : LV_GLOBAL, v->slot, 0};
    if (!at("[")) { error_at(peek()->line, "array needs an index:", name); return (lvalue_t){LV_NONE, 0, 0}; }
    expect("[");
    expression();
    expect("]");
    return (lvalue_t){local ? LV_LOCAL_ELEM : LV_GLOBAL_ELEM, v->slot, v->length};
}

static lvalue_t primary(void) {
    token_t* t = peek();
    lvalue_t none = {LV_NONE, 0, 0};
    if (t->kind == TK_NUMBER) {
        cc.pos++;
        emit8(OP_PUSH);
        emit32((uint32_t)t->value);
        return none;
    }
    if (t->kind == TK_STRING) {
        char joined[ACC_TOKEN_TEXT * 4];
        joined[0] = '\0';
        while (peek()->kind == TK_STRING) string_concat_n(joined, cc.tokens[cc.pos++].text, sizeof(joined));
        emit8(OP_PUSHS);
        emit32(add_string(joined));
        return none;
    }
    if (accept("(")) {
        expression();
        expect(")");
        return none;
    }
    if (t->kind == TK_IDENT) {
        cc.pos++;
        if (at("(")) {
            call(t->text);
            return none;
        }
        return variable(t->text);
    }
    error_here("expected an expression, found");
    return none;
}

static lvalue_t postfix(void) {
    lvalue_t lv = primary();
    if (at("++") || at("--")) {
        int8_t delta = at("++") ? 1 : -1;
        cc.pos++;
        adjust(lv, delta, true);
        lv.kind = LV_NONE;
    }
    return lv;
}

static bool cast_ahead(void) {
    if (!at("(")) return false;
    token_t* next = &cc.tokens[cc.pos + 1];
    return next->kind == TK_KEYWORD && (string_equals(next->text, "int") || string_equals(next->text, "char") ||
                                        string_equals(next->text, "void") || string_equals(next->text, "FILE"));
}

static lvalue_t unary(void) {
    lvalue_t none = {LV_NONE, 0, 0};
    if (at("-") || at("!") || at("~") || at("+")) {
        char op = peek()->text[0];
        cc.pos++;
        load(unary());
        if (op == '-') emit8(OP_NEG);
        else if (op == '!') emit8(OP_NOT);
        else if (op == '~') emit8(OP_BNOT);
        return none;
    }
    if (at("++") || at("--")) {
        int8_t delta = at("++") ? 1 : -1;
        cc.pos++;
        adjust(unary(), delta, false);
        return none;
    }
    if (cast_ahead()) {
        cc.pos++;
        parse_type();
        expect(")");
        load(unary());
        return none;
    }
    return postfix();
}

static const struct { const char* text; int prec; acc_opcode_t op; } binary_ops[] = {
    {"||", 1, OP_NOT}, {"&&", 2, OP_NOT}, {"|", 3, OP_OR}, {"^", 4, OP_XOR}, {"&", 5, OP_AND},
    {"==", 6, OP_EQ}, {"!=", 6, OP_NE}, {"<", 7, OP_LT}, {"<=", 7, OP_LE}, {">", 7, OP_GT},
    {">=", 7, OP_GE}, {"<<", 8, OP_SHL}, {">>", 8, OP_SHR}, {"+", 9, OP_ADD}, {"-", 9, OP_SUB},
    {"*", 10, OP_MUL}, {"/", 10, OP_DIV}, {"%", 10, OP_MOD}, {NULL, 0, OP_HALT}
};

static int32_t binary_op_at(void) {
    if (peek()->kind != TK_PUNCT) return -1;
    for (int32_t i = 0; binary_ops[i].text; i++) {
        if (string_equals(binary_ops[i].text, peek()->text)) return i;
    }
    return -1;
}

static void binary_rest(int min_prec);

static void operand(int prec) {
    load(unary());
    binary_rest(prec);
}

// Logical operators skip the right side and leave 0 or 1
static void short_circuit(bool is_or, int prec) {
    uint32_t skip_left = emit_jump(is_or ? OP_JNZ : OP_JZ);
    operand(prec + 1);
    uint32_t skip_right = emit_jump(is_or ? OP_JNZ : OP_JZ);
    emit8(OP_PUSH);
    emit32(is_or ? 0 : 1);
    uint32_t done = emit_jump(OP_JMP);
    patch_jump_here(skip_left);
    patch_jump_here(skip_right);
    emit8(OP_PUSH);
    emit32(is_or ? 1 : 0);
    patch_jump_here(done);
}

static void binary_rest(int min_prec) {
    int32_t index;
    while (!cc.has_error && (index = binary_op_at()) >= 0 && binary_ops[index].prec >= min_prec) {
        int prec = binary_ops[index].prec;
        cc.pos++;
        if (prec <= 2) {
            short_circuit(prec == 1, prec);
            continue;
        }
        operand(prec + 1);
        emit8(binary_ops[index].op);
    }
}

static void ternary_rest(void) {
    if (!accept("?")) return;
    uint32_t to_else = emit_jump(OP_JZ);
    expression();
    uint32_t to_end = emit_jump(OP_JMP);
    expect(":");
    patch_jump_here(to_else);
    expression();
    patch_jump_here(to_end);
}

static acc_opcode_t compound_op(const char* text) {
    static const struct { const char* text; acc_opcode_t op; } ops[] = {
        {"+=", OP_ADD}, {"-=", OP_SUB}, {"*=", OP_MUL}, {"/=", OP_DIV}, {"%=", OP_MOD}, {"&=", OP_AND},
        {"|=", OP_OR}, {"^=", OP_XOR}, {"<<=", OP_SHL}, {">>=", OP_SHR}, {NULL, OP_HALT}
    };
    for (int i = 0; ops[i].text; i++) {
        if (string_equals(ops[i].text, text)) return ops[i].op;
    }
    return OP_HALT;
}

static void assignment(lvalue_t lv, acc_opcode_t op) {
    bool element = lv.kind == LV_LOCAL_ELEM || lv.kind == LV_GLOBAL_ELEM;
    if (op != OP_HALT) {
        if (element) emit8(OP_DUP);
        load(lv);
    }
    expression();
    if (op != OP_HALT) emit8(op);
    store(lv);
}

static void expression(void) {
    lvalue_t lv = unary();
    token_t* t = peek();
    if (t->kind == TK_PUNCT && lv.kind != LV_NONE) {
        if (string_equals(t->text, "=")) {
            cc.pos++;
            assignment(lv, OP_HALT);
            return;
        }
        acc_opcode_t op = compound_op(t->text);
        if (op != OP_HALT) {
            cc.pos++;
            assignment(lv, op);
            return;
        }
    }
    load(lv);
    binary_rest(1);
    ternary_rest();
}

/* statements */

static void statement(void);

static void array_initializer(lvalue_kind_t kind, uint16_t slot, uint16_t length) {
    expect("{");
    uint16_t index = 0;
    while (!at("}") && !cc.has_error) {
        if (index >= length) { error_here("too many initializers near"); return; }
        emit8(OP_PUSH);
        emit32(index++);
        expression();
        store((lvalue_t){kind, slot, length});
        emit8(OP_POP);
        if (!accept(",")) break;
    }
    expect("}");
}

static uint16_t array_length(void) {
    if (!accept("[")) return 0;
    token_t* t = peek();
    if (t->kind != TK_NUMBER || t->value <= 0 || t->value > MAX_ARRAY_LENGTH) {
        error_here("array length must be a number from 1 to 4096, found");
        return 1;
    }
    cc.pos++;
    expect("]");
    return (uint16_t)t->value;
}

static void declaration_rest(bool global) {
    do {
        while (accept("*")) {}
        const char* name = expect_identifier();
        uint16_t length = array_length();
        uint16_t slot = global ? declare_global(name, length) : declare_local(name, length);
        lvalue_kind_t scalar = global ? LV_GLOBAL : LV_LOCAL;
        lvalue_kind_t element = global ? LV_GLOBAL_ELEM : LV_LOCAL_ELEM;
        if (accept("=")) {
            code_buffer_t* saved = cc.out;
            if (global) cc.out = &cc.init;
            if (length) {
                array_initializer(element, slot, length);
            } else {
                expression();
                store((lvalue_t){scalar, slot, 0});
                emit8(OP_POP);
            }
            cc.out = saved;
        }
    } while (accept(",") && !cc.has_error);
    expect(";");
}

static void block(void) {
    expect("{");
    cc.depth++;
    uint32_t saved_count = cc.local_count;
    uint32_t saved_slots = cc.local_slots;
    while (!at("}") && peek()->kind != TK_EOF && !cc.has_error) statement();
    expect("}");
    cc.local_count = saved_count;
    cc.local_slots = saved_slots;
    cc.depth--;
}

static void if_statement(void) {
    expect("(");
    expression();
    expect(")");
    uint32_t to_else = emit_jump(OP_JZ);
    statement();
    if (accept("else")) {
        uint32_t to_end = emit_jump(OP_JMP);
        patch_jump_here(to_else);
        statement();
        patch_jump_here(to_end);
    } else {
        patch_jump_here(to_else);
    }
}

static loop_t* begin_loop(void) {
    if (cc.loop_depth >= MAX_LOOP_DEPTH) { error_here("loops nested too deeply near"); return &cc.loops[0]; }
    loop_t* loop = &cc.loops[cc.loop_depth++];
    loop->break_count = 0;
    loop->continue_count = 0;
    return loop;
}

static void end_loop(loop_t* loop, uint32_t continue_target) {
    for (uint32_t i = 0; i < loop->continue_count; i++) patch_jump_to(loop->continues[i], continue_target);
    for (uint32_t i = 0; i < loop->break_count; i++) patch_jump_here(loop->breaks[i]);
    cc.loop_depth--;
}

static void while_statement(void) {
    uint32_t top = cc.out->size;
    expect("(");
    expression();
    expect(")");
    uint32_t to_end = emit_jump(OP_JZ);
    loop_t* loop = begin_loop();
    statement();
    emit_jump_back(OP_JMP, top);
    patch_jump_here(to_end);
    end_loop(loop, top);
}

// The step is compiled before the body and jumped over, so it can run after the body
static void for_statement(void) {
    cc.depth++;
    uint32_t saved_count = cc.local_count;
    uint32_t saved_slots = cc.local_slots;
    expect("(");
    if (at_type()) {
        parse_type();
        declaration_rest(false);
    } else {
        if (!at(";")) { expression(); emit8(OP_POP); }
        expect(";");
    }
    uint32_t condition = cc.out->size;
    uint32_t to_end = 0;
    bool has_condition = !at(";");
    if (has_condition) { expression(); to_end = emit_jump(OP_JZ); }
    expect(";");
    uint32_t to_body = emit_jump(OP_JMP);
    uint32_t step = cc.out->size;
    if (!at(")")) { expression(); emit8(OP_POP); }
    emit_jump_back(OP_JMP, condition);
    expect(")");
    patch_jump_here(to_body);
    loop_t* loop = begin_loop();
    statement();
    emit_jump_back(OP_JMP, step);
    if (has_condition) patch_jump_here(to_end);
    end_loop(loop, step);
    cc.local_count = saved_count;
    cc.local_slots = saved_slots;
    cc.depth--;
}

static void loop_jump(bool is_break) {
    if (cc.loop_depth == 0) { error_here("break or continue outside a loop near"); return; }
    loop_t* loop = &cc.loops[cc.loop_depth - 1];
    uint32_t* count = is_break ? &loop->break_count : &loop->continue_count;
    if (*count >= MAX_LOOP_JUMPS) { error_here("too many jumps in one loop near"); return; }
    uint32_t operand = emit_jump(OP_JMP);
    if (is_break) loop->breaks[(*count)++] = operand;
    else loop->continues[(*count)++] = operand;
    expect(";");
}

static void statement(void) {
    if (at("{")) { block(); return; }
    if (accept(";")) return;
    if (at_type()) { parse_type(); declaration_rest(false); return; }
    if (accept("if")) { if_statement(); return; }
    if (accept("while")) { while_statement(); return; }
    if (accept("for")) { for_statement(); return; }
    if (accept("break")) { loop_jump(true); return; }
    if (accept("continue")) { loop_jump(false); return; }
    if (accept("return")) {
        if (at(";")) { emit8(OP_PUSH); emit32(0); }
        else expression();
        emit8(OP_RET);
        expect(";");
        return;
    }
    expression();
    emit8(OP_POP);
    expect(";");
}

/* top level */

static int32_t parameters(void) {
    int32_t count = 0;
    expect("(");
    if (at("void") && cc.tokens[cc.pos + 1].kind == TK_PUNCT && string_equals(cc.tokens[cc.pos + 1].text, ")")) {
        cc.pos++;
    } else if (!at(")")) {
        do {
            parse_type();
            declare_local(expect_identifier(), 0);
            count++;
        } while (accept(",") && !cc.has_error);
    }
    expect(")");
    return count;
}

static void function_definition(const char* name) {
    cc.local_count = 0;
    cc.local_slots = 0;
    cc.max_local_slots = 0;
    cc.depth = 1;
    int32_t params = parameters();
    int32_t index = declare_function(name, params);
    if (accept(";")) return;
    if (cc.functions[index].address != UNRESOLVED) { error_at(peek()->line, "function defined twice:", name); return; }
    cc.functions[index].address = cc.funcs.size;
    emit8(OP_ENTER);
    uint32_t enter_operand = cc.out->size;
    emit16(0);
    block();
    emit8(OP_PUSH);
    emit32(0);
    emit8(OP_RET);
    cc.funcs.bytes[enter_operand] = (uint8_t)cc.max_local_slots;
    cc.funcs.bytes[enter_operand + 1] = (uint8_t)(cc.max_local_slots >> 8);
}

static void top_level(void) {
    while (peek()->kind != TK_EOF && !cc.has_error) {
        parse_type();
        uint32_t name_pos = cc.pos;
        const char* name = expect_identifier();
        if (at("(")) {
            function_definition(name);
        } else {
            cc.pos = name_pos;
            declaration_rest(true);
        }
    }
}

static bool resolve_calls(void) {
    for (uint32_t i = 0; i < cc.fixup_count; i++) {
        function_t* f = &cc.functions[cc.fixups[i].function];
        if (f->address == UNRESOLVED) {
            error_at(0, "function is declared but never defined:", f->name);
            return false;
        }
        patch32(cc.fixups[i].in_init ? &cc.init : &cc.funcs, cc.fixups[i].offset, f->address);
    }
    return true;
}

static void write_u32(uint8_t* at_byte, uint32_t value) {
    for (int i = 0; i < 4; i++) at_byte[i] = (uint8_t)(value >> (8 * i));
}

// Layout is functions, then global initializers, then a call to main and a halt
static bool link_image(void) {
    int32_t main_index = find_function("main");
    if (main_index < 0 || cc.functions[main_index].address == UNRESOLVED) {
        error_at(0, "no main function", NULL);
        return false;
    }
    cc.out = &cc.init;
    uint32_t entry = cc.funcs.size;
    emit8(OP_CALL);
    cc.fixups[cc.fixup_count++] = (fixup_t){true, cc.init.size, (uint32_t)main_index};
    emit32(0);
    emit8((uint8_t)cc.functions[main_index].params);
    emit8(OP_HALT);
    if (cc.has_error || !resolve_calls()) return false;

    uint32_t code_size = cc.funcs.size + cc.init.size;
    uint8_t* image = cc.image;
    image[0] = ACC_MAGIC_0; image[1] = ACC_MAGIC_1; image[2] = ACC_MAGIC_2; image[3] = ACC_MAGIC_3;
    write_u32(image + 4, entry);
    write_u32(image + 8, code_size);
    write_u32(image + 12, cc.data_size);
    write_u32(image + 16, cc.global_slots);
    uint32_t pos = ACC_HEADER_SIZE;
    for (uint32_t i = 0; i < cc.funcs.size; i++) image[pos++] = cc.funcs.bytes[i];
    for (uint32_t i = 0; i < cc.init.size; i++) image[pos++] = cc.init.bytes[i];
    for (uint32_t i = 0; i < cc.data_size; i++) image[pos++] = cc.data[i];
    cc.image_size = pos;
    return true;
}

void acc_initialize(void) {
    cc.token_count = 0;
    cc.pos = 0;
    cc.macro_count = 0;
    cc.funcs = (code_buffer_t){cc.func_code, 0};
    cc.init = (code_buffer_t){cc.init_code, 0};
    cc.out = &cc.funcs;
    cc.data_size = 0;
    cc.global_count = 0;
    cc.global_slots = 0;
    cc.function_count = 0;
    cc.fixup_count = 0;
    cc.local_count = 0;
    cc.loop_depth = 0;
    cc.image_size = 0;
    cc.has_error = false;
    cc.error[0] = '\0';
}

static compile_result_t compile(const char* source) {
    acc_initialize();
    tokenize(source);
    if (!cc.has_error) top_level();
    if (!cc.has_error) link_image();
    return cc.has_error ? COMPILE_ERROR_SYNTAX : COMPILE_SUCCESS;
}

static void set_error(const char* message, const char* path) {
    cc.has_error = true;
    string_copy(cc.error, message);
    string_concat_n(cc.error, ": ", ERROR_TEXT);
    string_concat_n(cc.error, path, ERROR_TEXT);
}

static char source_text[FS_TOOL_BUFFER_SIZE + 1];

static compile_result_t compile_source_file(const char* source_file) {
    acc_initialize();
    fs_file_handle_t* in = filesystem_open_file(source_file, false);
    if (!in) { set_error("cannot open source file", source_file); return COMPILE_ERROR_FILE; }
    uint32_t length = filesystem_read_file(in, source_text, FS_TOOL_BUFFER_SIZE);
    filesystem_close_file(in);
    source_text[length] = '\0';
    return compile(source_text);
}

compile_result_t acc_compile_file_native(const char* source_file, const char* output_file) {
    compile_result_t result = compile_source_file(source_file);
    if (result != COMPILE_SUCCESS) return result;
    char error[ACC_NATIVE_ERROR_LENGTH];
    if (!acc_native_write(cc.image, cc.image_size, output_file, error)) {
        set_error(error, output_file);
        return COMPILE_ERROR_FILE;
    }
    return COMPILE_SUCCESS;
}

compile_result_t acc_compile_file(const char* source_file, const char* output_file) {
    compile_result_t result = compile_source_file(source_file);
    if (result != COMPILE_SUCCESS) return result;

    if (filesystem_file_exists(output_file) && !filesystem_delete_file(output_file)) {
        set_error("output path exists and is not a file", output_file);
        return COMPILE_ERROR_FILE;
    }
    if (!filesystem_create_file(output_file)) { set_error("cannot create output file", output_file); return COMPILE_ERROR_FILE; }
    fs_file_handle_t* out = filesystem_open_file(output_file, true);
    if (!out) { set_error("cannot open output file", output_file); return COMPILE_ERROR_FILE; }
    uint32_t written = filesystem_write_file(out, cc.image, cc.image_size);
    filesystem_close_file(out);
    if (written != cc.image_size) { set_error("program does not fit in one file block", output_file); return COMPILE_ERROR_FILE; }
    return COMPILE_SUCCESS;
}

compile_result_t acc_compile_string(const char* source_code, uint8_t* output_buffer, uint32_t* output_size) {
    compile_result_t result = compile(source_code);
    if (result != COMPILE_SUCCESS || !output_buffer || !output_size) return result;
    if (cc.image_size > *output_size) return COMPILE_ERROR_MEMORY;
    for (uint32_t i = 0; i < cc.image_size; i++) output_buffer[i] = cc.image[i];
    *output_size = cc.image_size;
    return COMPILE_SUCCESS;
}

const char* acc_get_error_message(void) {
    return cc.error;
}

void acc_print_version(void) {
    terminal_write_string("Apollo C Compiler (acc) 2.0, C subset to stack bytecode\n");
}
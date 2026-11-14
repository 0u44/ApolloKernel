#include "runtime.h"

#define CP_ACP 0
#define CP_OEMCP 1
#define CP_THREAD_ACP 3
#define CP_UTF8 65001
#define MB_ERR_INVALID_CHARS 0x08
#define WC_ERR_INVALID_CHARS 0x80
#define UTF8_MAX_CHAR_SIZE 4
#define LOCALE_EN_US 0x0409
#define LOCALE_INVARIANT 0x007F
#define LOCALE_USER_DEFAULT 0x0400
#define LOCALE_SYSTEM_DEFAULT 0x0800
#define LOCALE_RETURN_NUMBER 0x20000000u
#define LOCALE_NOUSEROVERRIDE 0x80000000u
#define LOCALE_IDEFAULTCODEPAGE 0x000B
#define LOCALE_SDECIMAL 0x000E
#define LOCALE_STHOUSAND 0x000F
#define LOCALE_SGROUPING 0x0010
#define LOCALE_SNAME 0x005C
#define LOCALE_SISO639LANGNAME 0x0059
#define LOCALE_SISO3166CTRYNAME 0x005A
#define LOCALE_SENGLANGUAGE 0x1001
#define LOCALE_SENGCOUNTRY 0x1002
#define LOCALE_IDEFAULTANSICODEPAGE 0x1004
#define LCMAP_LOWERCASE 0x0100
#define LCMAP_UPPERCASE 0x0200
#define NORM_IGNORECASE 0x0001
#define CSTR_LESS_THAN 1
#define CSTR_EQUAL 2
#define CSTR_GREATER_THAN 3
#define CT_CTYPE1 1
#define CT_CTYPE2 2
#define CT_CTYPE3 4
#define C1_UPPER 0x0001
#define C1_LOWER 0x0002
#define C1_DIGIT 0x0004
#define C1_SPACE 0x0008
#define C1_PUNCT 0x0010
#define C1_CNTRL 0x0020
#define C1_BLANK 0x0040
#define C1_XDIGIT 0x0080
#define C1_ALPHA 0x0100
#define C1_DEFINED 0x0200
#define C2_LEFTTORIGHT 0x1
#define C2_EUROPENUMBER 0x3
#define C2_WHITESPACE 0xA
#define C2_OTHERNEUTRAL 0xB
#define C3_SYMBOL 0x0008
#define C3_ALPHA 0x8000
#define LATIN1_LAST 0xFF
#define LATIN1_MULTIPLY 0xD7
#define LATIN1_DIVIDE 0xF7
#define LATIN1_SHARP_S 0xDF
#define LATIN1_Y_DIAERESIS 0xFF
#define CASE_OFFSET 0x20
#define LOCALE_NAME_LENGTH 85

typedef BOOL (WINAPI *locale_callback_t)(WCHAR* name);

typedef struct {
    UINT max_char_size;
    uint8_t default_char[2];
    uint8_t lead_byte[12];
} CPINFO;

static bool utf8_page(UINT page) {
    return page == CP_ACP || page == CP_OEMCP || page == CP_THREAD_ACP || page == CP_UTF8;
}

WINAPI UINT GetACP(void) {
    return CP_UTF8;
}

WINAPI UINT GetOEMCP(void) {
    return CP_UTF8;
}

WINAPI BOOL IsValidCodePage(UINT page) {
    return page == CP_UTF8;
}

WINAPI BOOL GetCPInfo(UINT page, CPINFO* info) {
    if (!utf8_page(page)) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    memset(info, 0, sizeof(*info));
    info->max_char_size = UTF8_MAX_CHAR_SIZE;
    info->default_char[0] = '?';
    return TRUE;
}

WINAPI int MultiByteToWideChar(UINT page, DWORD flags, const char* in, int in_length, WCHAR* out, int out_size) {
    if (!utf8_page(page) || !in || out_size < 0) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    uint32_t length = in_length < 0 ? (uint32_t)rt_strlen(in) + 1 : (uint32_t)in_length;
    bool invalid = false;
    uint32_t needed = rt_utf8_to_utf16(in, length, NULL, 0, &invalid);
    if (invalid && (flags & MB_ERR_INVALID_CHARS)) {
        rt_set_last_error(ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }
    if (out_size == 0) return (int)needed;
    if (needed > (uint32_t)out_size) {
        rt_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    rt_utf8_to_utf16(in, length, out, (uint32_t)out_size, &invalid);
    return (int)needed;
}

WINAPI int WideCharToMultiByte(UINT page, DWORD flags, const WCHAR* in, int in_length, char* out, int out_size,
                               const char* default_char, BOOL* used_default) {
    if (!utf8_page(page) || !in || out_size < 0 || default_char || used_default) {
        rt_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    uint32_t length = in_length < 0 ? (uint32_t)rt_wcslen(in) + 1 : (uint32_t)in_length;
    bool invalid = false;
    uint32_t needed = rt_utf16_to_utf8(in, length, NULL, 0, &invalid);
    if (invalid && (flags & WC_ERR_INVALID_CHARS)) {
        rt_set_last_error(ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }
    if (out_size == 0) return (int)needed;
    if (needed > (uint32_t)out_size) {
        rt_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    rt_utf16_to_utf8(in, length, out, (uint32_t)out_size, &invalid);
    return (int)needed;
}

static bool latin1_upper(WCHAR c) {
    return (c >= 'A' && c <= 'Z') || (c >= 0xC0 && c <= 0xDE && c != LATIN1_MULTIPLY);
}

static bool latin1_lower(WCHAR c) {
    return (c >= 'a' && c <= 'z') || (c >= LATIN1_SHARP_S && c <= LATIN1_LAST && c != LATIN1_DIVIDE) || c == 0xAA || c == 0xB5 || c == 0xBA;
}

static uint16_t ctype1(WCHAR c) {
    if (c > LATIN1_LAST) return C1_ALPHA | C1_DEFINED;
    uint16_t t = C1_DEFINED;
    if (latin1_upper(c)) t |= C1_UPPER | C1_ALPHA;
    if (latin1_lower(c)) t |= C1_LOWER | C1_ALPHA;
    if (c >= '0' && c <= '9') t |= C1_DIGIT | C1_XDIGIT;
    if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) t |= C1_XDIGIT;
    if ((c >= 0x09 && c <= 0x0D) || c == ' ' || c == 0x85 || c == 0xA0) t |= C1_SPACE;
    if (c == ' ' || c == '\t' || c == 0xA0) t |= C1_BLANK;
    if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) t |= C1_CNTRL;
    bool punct = (c > 0x20 && c < 0x7F) || (c >= 0xA1 && c <= 0xBF);
    if (punct && !(t & (C1_ALPHA | C1_DIGIT))) t |= C1_PUNCT;
    return t;
}

static uint16_t ctype2(WCHAR c) {
    uint16_t t = ctype1(c);
    if (t & C1_ALPHA) return C2_LEFTTORIGHT;
    if (t & C1_DIGIT) return C2_EUROPENUMBER;
    if (t & C1_SPACE) return C2_WHITESPACE;
    return C2_OTHERNEUTRAL;
}

static uint16_t ctype3(WCHAR c) {
    uint16_t t = ctype1(c);
    if (t & C1_ALPHA) return C3_ALPHA;
    return (t & C1_PUNCT) ? C3_SYMBOL : 0;
}

static WCHAR to_upper(WCHAR c) {
    if ((c >= 'a' && c <= 'z') || (c >= 0xE0 && c <= 0xFE && c != LATIN1_DIVIDE)) return (WCHAR)(c - CASE_OFFSET);
    return c;
}

static WCHAR to_lower(WCHAR c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 0xC0 && c <= 0xDE && c != LATIN1_MULTIPLY)) return (WCHAR)(c + CASE_OFFSET);
    return c;
}

WINAPI BOOL GetStringTypeW(DWORD type, const WCHAR* text, int length, uint16_t* out) {
    if (type != CT_CTYPE1 && type != CT_CTYPE2 && type != CT_CTYPE3) {
        rt_set_last_error(ERROR_INVALID_FLAGS);
        return FALSE;
    }
    uint32_t n = length < 0 ? (uint32_t)rt_wcslen(text) + 1 : (uint32_t)length;
    for (uint32_t i = 0; i < n; i++) {
        out[i] = type == CT_CTYPE1 ? ctype1(text[i]) : type == CT_CTYPE2 ? ctype2(text[i]) : ctype3(text[i]);
    }
    return TRUE;
}

static int map_string(DWORD flags, const WCHAR* in, int in_length, WCHAR* out, int out_size) {
    if ((flags & ~(DWORD)(LCMAP_LOWERCASE | LCMAP_UPPERCASE)) || flags == (LCMAP_LOWERCASE | LCMAP_UPPERCASE)) {
        rt_set_last_error(ERROR_INVALID_FLAGS);
        return 0;
    }
    uint32_t n = in_length < 0 ? (uint32_t)rt_wcslen(in) + 1 : (uint32_t)in_length;
    if (out_size == 0) return (int)n;
    if (n > (uint32_t)out_size) {
        rt_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    for (uint32_t i = 0; i < n; i++) {
        out[i] = (flags & LCMAP_UPPERCASE) ? to_upper(in[i]) : (flags & LCMAP_LOWERCASE) ? to_lower(in[i]) : in[i];
    }
    return (int)n;
}

WINAPI int LCMapStringW(LCID locale, DWORD flags, const WCHAR* in, int in_length, WCHAR* out, int out_size) {
    (void)locale;
    return map_string(flags, in, in_length, out, out_size);
}

WINAPI int LCMapStringEx(const WCHAR* locale, DWORD flags, const WCHAR* in, int in_length, WCHAR* out, int out_size,
                         void* version, void* reserved, LONG_PTR parameter) {
    (void)locale; (void)version; (void)reserved; (void)parameter;
    return map_string(flags, in, in_length, out, out_size);
}

WINAPI int CompareStringW(LCID locale, DWORD flags, const WCHAR* a, int a_length, const WCHAR* b, int b_length) {
    (void)locale;
    uint32_t na = a_length < 0 ? (uint32_t)rt_wcslen(a) : (uint32_t)a_length;
    uint32_t nb = b_length < 0 ? (uint32_t)rt_wcslen(b) : (uint32_t)b_length;
    for (uint32_t i = 0; i < na && i < nb; i++) {
        WCHAR x = (flags & NORM_IGNORECASE) ? to_upper(a[i]) : a[i];
        WCHAR y = (flags & NORM_IGNORECASE) ? to_upper(b[i]) : b[i];
        if (x != y) return x < y ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
    }
    return na == nb ? CSTR_EQUAL : (na < nb ? CSTR_LESS_THAN : CSTR_GREATER_THAN);
}

static const struct {
    DWORD type;
    const char* text;
    DWORD number;
} locale_values[] = {
    {LOCALE_IDEFAULTCODEPAGE, "65001", CP_UTF8}, {LOCALE_IDEFAULTANSICODEPAGE, "65001", CP_UTF8},
    {LOCALE_SDECIMAL, ".", 0}, {LOCALE_STHOUSAND, ",", 0}, {LOCALE_SGROUPING, "3;0", 0},
    {LOCALE_SNAME, "en-US", 0}, {LOCALE_SISO639LANGNAME, "en", 0}, {LOCALE_SISO3166CTRYNAME, "US", 0},
    {LOCALE_SENGLANGUAGE, "English", 0}, {LOCALE_SENGCOUNTRY, "United States", 0},
};

static bool known_locale(LCID locale) {
    return locale == LOCALE_EN_US || locale == LOCALE_INVARIANT || locale == LOCALE_USER_DEFAULT || locale == LOCALE_SYSTEM_DEFAULT || locale == 0;
}

WINAPI int GetLocaleInfoW(LCID locale, DWORD type, WCHAR* out, int out_size) {
    DWORD plain = type & ~(LOCALE_RETURN_NUMBER | LOCALE_NOUSEROVERRIDE);
    for (uint32_t i = 0; known_locale(locale) && i < ARRAY_SIZE(locale_values); i++) {
        if (locale_values[i].type != plain) continue;
        if (type & LOCALE_RETURN_NUMBER) {
            int needed = (int)(sizeof(DWORD) / sizeof(WCHAR));
            if (out_size == 0) return needed;
            if (out_size < needed) break;
            memcpy(out, &locale_values[i].number, sizeof(DWORD));
            return needed;
        }
        uint32_t n = (uint32_t)rt_strlen(locale_values[i].text) + 1;
        if (out_size == 0) return (int)n;
        if ((uint32_t)out_size < n) {
            rt_set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        for (uint32_t j = 0; j < n; j++) out[j] = (WCHAR)locale_values[i].text[j];
        return (int)n;
    }
    rt_set_last_error(known_locale(locale) ? ERROR_INVALID_FLAGS : ERROR_INVALID_PARAMETER);
    return 0;
}

WINAPI LCID GetUserDefaultLCID(void) {
    return LOCALE_EN_US;
}

WINAPI BOOL IsValidLocale(LCID locale, DWORD flags) {
    (void)flags;
    return locale == LOCALE_EN_US || locale == LOCALE_INVARIANT;
}

WINAPI BOOL EnumSystemLocalesW(locale_callback_t callback, DWORD flags) {
    (void)flags;
    WCHAR name[] = u"00000409";
    callback(name);
    return TRUE;
}
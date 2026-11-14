#include "command_processor.h"
#include "terminal.h"
#include "input_manager.h"
#include "time_keeper.h"
#include "heap_allocator.h"
#include "text_editor.h"
#include "filesystem.h"
#include "process_manager.h"
#include "network_manager.h"
#include "pci_scan.h"
#include "intel_e1000.h"
#include "rtl8139_driver.h"
#include "tcp_stack.h"
#include "firewall.h"
#include "rate_limiter.h"
#include "crypto.h"
#include "security_audit.h"
#include "secure_boot.h"
#include "audio_subsystem.h"
#include "hda_driver.h"
#include "wave_player.h"
#include "types.h"
#include "acc_compiler.h"
#include "abuild.h"
#include "executor.h"
#include "net_commands.h"
#include "program.h"

#define MAX_COMMAND_LENGTH 256
#define MAX_ARGUMENTS 16
#define COMMAND_HISTORY_SIZE 32

#define INT32_MAX 2147483647
#define INT32_MIN (-2147483647 - 1)

typedef struct {
    char buffer[MAX_COMMAND_LENGTH];
    uint32_t length;
    uint32_t cursor_position;
} command_line_t;

typedef struct {
    char entries[COMMAND_HISTORY_SIZE][MAX_COMMAND_LENGTH];
    uint32_t count;
    uint32_t write_index;
    int32_t browse_index;
} command_history_t;

typedef struct {
    bool advanced_mode;
    bool initialized;
    char current_user[32];
    uint32_t commands_executed;
    uint32_t shell_start_time;
    uint32_t session_id;
    bool echo_mode;
} shell_state_t;

static command_line_t current_command = {0};
static command_history_t history = {0};
static shell_state_t shell = {0};

static void initialize_security_subsystems(void);
static void initialize_network_security_subsystems(void);

static bool security_initialized = false;
static bool network_init_attempted = false;

static uint32_t string_length(const char* str) {
    uint32_t len = 0;
    while (str && str[len] != '\0') len++;
    return len;
}

static int string_compare(const char* str1, const char* str2) {
    while (*str1 && *str2 && *str1 == *str2) {
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

static void string_append(char* dest, const char* src) {
    while (*dest) dest++;
    while (*src) *dest++ = *src++;
    *dest = '\0';
}

static uint32_t strlen(const char* str) {
    uint32_t len = 0;
    while (str[len]) len++;
    return len;
}

static bool command_starts_with(const char* str, const char* prefix) {
    if (!str || !prefix) return false;

    while (*prefix) {
        if (*str != *prefix) return false;
        str++;
        prefix++;
    }
    return true;
}

static int string_to_integer(const char* str) {
    if (!str) return 0;

    int result = 0;
    int sign = 1;

    while (*str == ' ' || *str == '\t') str++;

    if (*str == '-') {
        sign = -1;
        str++;
    } else if (*str == '+') {
        str++;
    }

    while (*str >= '0' && *str <= '9') {
        result = result * 10 + (*str - '0');
        str++;
    }

    return result * sign;
}

static bool string_to_integer_safe(const char* str, int* result) {
    if (!str || !result) return false;

    *result = 0;
    int sign = 1;

    while (*str == ' ' || *str == '\t') str++;

    if (*str == '-') {
        sign = -1;
        str++;
    } else if (*str == '+') {
        str++;
    }

    if (*str < '0' || *str > '9') return false;

    while (*str >= '0' && *str <= '9') {
        int digit = *str - '0';

        if (*result > (INT32_MAX - digit) / 10) {
            return false;
        }

        *result = *result * 10 + digit;
        str++;
    }

    while (*str == ' ' || *str == '\t') str++;
    if (*str != '\0') return false;

    *result *= sign;
    return true;
}

static bool string_contains(const char* haystack, const char* needle) {
    uint32_t needle_len = string_length(needle);
    uint32_t haystack_len = string_length(haystack);

    if (needle_len > haystack_len) return false;

    for (uint32_t i = 0; i <= haystack_len - needle_len; i++) {
        bool match = true;
        for (uint32_t j = 0; j < needle_len; j++) {
            if (haystack[i + j] != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

uint32_t string_to_uint(const char* str) {
    uint32_t result = 0;
    while (*str >= '0' && *str <= '9') {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

static uint32_t parse_arguments(const char* input, char args[MAX_ARGUMENTS][MAX_COMMAND_LENGTH]) {
    uint32_t arg_count = 0;
    uint32_t arg_pos = 0;
    bool in_argument = false;

    for (uint32_t i = 0; input[i] && arg_count < MAX_ARGUMENTS; i++) {
        if (input[i] == ' ' || input[i] == '\t') {
            if (in_argument) {
                args[arg_count][arg_pos] = '\0';
                arg_count++;
                arg_pos = 0;
                in_argument = false;
            }
        } else {
            if (!in_argument) {
                in_argument = true;
            }
            if (arg_pos < MAX_COMMAND_LENGTH - 1) {
                args[arg_count][arg_pos++] = input[i];
            }
        }
    }

    if (in_argument) {
        args[arg_count][arg_pos] = '\0';
        arg_count++;
    }

    return arg_count;
}

static void add_command_to_history(const char* command) {
    if (string_length(command) == 0) return;

    string_copy(history.entries[history.write_index], command);
    history.write_index = (history.write_index + 1) % COMMAND_HISTORY_SIZE;
    if (history.count < COMMAND_HISTORY_SIZE) {
        history.count++;
    }
    history.browse_index = -1;
    shell.commands_executed++;
}

static void browse_history(bool go_up) {
    if (history.count == 0) return;

    if (go_up) {
        if (history.browse_index == -1) {
            history.browse_index = 0;
        } else if (history.browse_index < (int32_t)history.count - 1) {
            history.browse_index++;
        }
    } else {
        if (history.browse_index > 0) {
            history.browse_index--;
        } else {
            history.browse_index = -1;
            current_command.length = 0;
            current_command.cursor_position = 0;
            return;
        }
    }

    while (current_command.cursor_position > 0) {
        terminal_backspace();
        current_command.cursor_position--;
    }

    uint32_t hist_idx = (history.write_index - 1 - history.browse_index + COMMAND_HISTORY_SIZE) % COMMAND_HISTORY_SIZE;
    string_copy(current_command.buffer, history.entries[hist_idx]);
    current_command.length = string_length(current_command.buffer);
    current_command.cursor_position = current_command.length;

    for (uint32_t i = 0; i < current_command.length; i++) {
        terminal_write_char(current_command.buffer[i]);
    }
}

static int calculate_expression(const char* expr) {
    if (!expr) return 0;

    char tokens[MAX_ARGUMENTS][MAX_COMMAND_LENGTH];
    uint32_t token_count = parse_arguments(expr, tokens);

    if (token_count == 0) {
        return 0;
    }

    if (token_count % 2 == 0) {
        return 0;
    }

    int result;
    if (!string_to_integer_safe(tokens[0], &result)) {
        return 0;
    }

    for (uint32_t i = 1; i < token_count; i += 2) {
        if (i + 1 >= token_count) {
            return 0;
        }

        if (string_length(tokens[i]) != 1) {
            return 0;
        }
        char op = tokens[i][0];

        int operand;
        if (!string_to_integer_safe(tokens[i + 1], &operand)) {
            return 0;
        }

        switch (op) {
            case '+':
                if ((operand > 0 && result > INT32_MAX - operand) ||
                    (operand < 0 && result < INT32_MIN - operand)) {
                    return 0;
                }
                result += operand;
                break;

            case '-':
                if ((operand < 0 && result > INT32_MAX + operand) ||
                    (operand > 0 && result < INT32_MIN + operand)) {
                    return 0;
                }
                result -= operand;
                break;

            case '*':
            case 'x':
            case 'X':
                if (operand != 0) {
                    if ((result > 0 && operand > 0 && result > INT32_MAX / operand) ||
                        (result > 0 && operand < 0 && operand < INT32_MIN / result) ||
                        (result < 0 && operand > 0 && result < INT32_MIN / operand) ||
                        (result < 0 && operand < 0 && result < INT32_MAX / operand)) {
                        return 0;
                    }
                }
                result *= operand;
                break;

            case '/':
                if (operand == 0) {
                    return 0; // Division by zero
                }
                if (result == INT32_MIN && operand == -1) {
                    return 0;
                }
                result /= operand;
                break;

            case '%':
                if (operand == 0) {
                    return 0; // Modulo by zero
                }
                result %= operand;
                break;

            default:
                return 0;
        }
    }

    return result;
}

static bool command_security_audit(char* args[], int argc) {
    if (argc < 1) {
        terminal_write_string("\nUsage: secaudit [--full|--quick|--network|--detailed|--summary]\n");
        terminal_write_string("Security audit commands:\n");
        terminal_write_string("  --full      Run comprehensive security audit\n");
        terminal_write_string("  --quick     Run quick security scan\n");
        terminal_write_string("  --network   Run network security audit only\n");
        terminal_write_string("  --detailed  Show detailed audit report\n");
        terminal_write_string("  --summary   Show audit summary\n");
        terminal_write_string("  --monitor   Start continuous monitoring\n");
        terminal_write_string("  --stop      Stop continuous monitoring\n");
        return true;
    }

    security_audit_result_t* result = NULL;

    if (string_compare(args[0], "--full") == 0) {
        terminal_write_string("Starting comprehensive security audit...\n");
        result = security_audit_run_full_scan();
    } else if (string_compare(args[0], "--quick") == 0) {
        terminal_write_string("Starting quick security scan...\n");
        result = security_audit_run_quick_scan();
    } else if (string_compare(args[0], "--network") == 0) {
        terminal_write_string("Starting network security audit...\n");
        result = security_audit_run_network_scan();
    } else if (string_compare(args[0], "--detailed") == 0) {
        result = security_audit_run_full_scan();
        if (result) {
            security_audit_print_detailed_report(result);
        }
        return true;
    } else if (string_compare(args[0], "--summary") == 0) {
        result = security_audit_run_full_scan();
        if (result) {
            security_audit_print_summary(result);
        }
        return true;
    } else if (string_compare(args[0], "--monitor") == 0) {
        if (security_audit_start_continuous_monitoring()) {
            terminal_write_string("Continuous security monitoring started\n");
        } else {
            terminal_write_string("Failed to start continuous monitoring\n");
        }
        return true;
    } else if (string_compare(args[0], "--stop") == 0) {
        security_audit_stop_continuous_monitoring();
        terminal_write_string("Continuous security monitoring stopped\n");
        return true;
    } else {
        terminal_write_string("Unknown audit option. Use --help for usage.\n");
        return false;
    }

    if (result) {
        security_audit_print_summary(result);
    } else {
        terminal_write_string("Security audit failed to complete\n");
    }

    return true;
}

#define IPV4_BITS 32

static void write_padded(const char* text, uint32_t width) {
    uint32_t length = string_length(text);
    terminal_write_string(text);
    while (length++ < width) terminal_write_char(' ');
}

static uint32_t format_uint(char* out, uint32_t value) {
    char digits[11];
    uint32_t count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value > 0);
    for (uint32_t i = 0; i < count; i++) out[i] = digits[count - 1 - i];
    out[count] = '\0';
    return count;
}

static void write_padded_uint(uint32_t value, uint32_t width) {
    char text[12];
    format_uint(text, value);
    write_padded(text, width);
}

// Accepts a.b.c.d or a.b.c.d/prefix and returns both in network byte order
static bool parse_ip_prefix(const char* text, ip_address_t* network, ip_address_t* netmask) {
    char address[16];
    uint32_t i = 0;
    while (text[i] && text[i] != '/' && i < sizeof(address) - 1) {
        address[i] = text[i];
        i++;
    }
    address[i] = '\0';
    if (!string_to_ip_address(address, network)) return false;
    uint32_t prefix = IPV4_BITS;
    if (text[i] == '/') {
        prefix = string_to_uint(&text[i + 1]);
        if (prefix > IPV4_BITS) return false;
    }
    uint32_t host_mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (IPV4_BITS - prefix);
    netmask->addr = __builtin_bswap32(host_mask);
    return true;
}

static bool parse_port_range(const char* text, port_range_t* range) {
    uint32_t start = string_to_uint(text);
    uint32_t end = start;
    for (uint32_t i = 0; text[i]; i++) {
        if (text[i] == '-') {
            end = string_to_uint(&text[i + 1]);
            break;
        }
    }
    if (start == 0 || start > 0xFFFF || end < start || end > 0xFFFF) return false;
    range->start = (uint16_t)start;
    range->end = (uint16_t)end;
    return true;
}

static bool parse_fw_action(const char* text, firewall_action_t* action) {
    if (string_compare(text, "allow") == 0) *action = FIREWALL_ACTION_ALLOW;
    else if (string_compare(text, "deny") == 0) *action = FIREWALL_ACTION_DENY;
    else if (string_compare(text, "drop") == 0) *action = FIREWALL_ACTION_DROP;
    else if (string_compare(text, "reject") == 0) *action = FIREWALL_ACTION_REJECT;
    else if (string_compare(text, "log") == 0) *action = FIREWALL_ACTION_LOG;
    else return false;
    return true;
}

static bool parse_fw_direction(const char* text, firewall_direction_t* direction) {
    if (string_compare(text, "in") == 0) *direction = FIREWALL_DIR_IN;
    else if (string_compare(text, "out") == 0) *direction = FIREWALL_DIR_OUT;
    else if (string_compare(text, "both") == 0) *direction = FIREWALL_DIR_BOTH;
    else return false;
    return true;
}

static bool parse_protocol(const char* text, uint8_t* protocol) {
    if (string_compare(text, "tcp") == 0) *protocol = FIREWALL_PROTO_TCP;
    else if (string_compare(text, "udp") == 0) *protocol = FIREWALL_PROTO_UDP;
    else if (string_compare(text, "icmp") == 0) *protocol = FIREWALL_PROTO_ICMP;
    else if (string_compare(text, "any") == 0) *protocol = FIREWALL_PROTO_ANY;
    else return false;
    return true;
}

static const char* protocol_name(uint8_t protocol) {
    switch (protocol) {
        case FIREWALL_PROTO_TCP: return "tcp";
        case FIREWALL_PROTO_UDP: return "udp";
        case FIREWALL_PROTO_ICMP: return "icmp";
    }
    return "any";
}

static const char* direction_name(firewall_direction_t direction) {
    if (direction == FIREWALL_DIR_IN) return "in";
    if (direction == FIREWALL_DIR_OUT) return "out";
    return "both";
}

static void print_firewall_rules(void) {
    uint32_t count = firewall_get_rule_count();
    terminal_write_string("\nID  On  Dir  Proto Dst port     Action  Matches  Description\n");
    for (uint32_t i = 0; i < count; i++) {
        firewall_rule_t r;
        if (!firewall_get_rule_at(i, &r)) continue;
        write_padded_uint(r.rule_id, 4);
        write_padded(r.enabled ? "yes" : "no", 4);
        write_padded(direction_name(r.direction), 5);
        write_padded(protocol_name(r.protocol), 6);
        if (r.dst_port_count > 0) {
            char range[16];
            uint32_t pos = format_uint(range, r.dst_ports[0].start);
            if (r.dst_ports[0].end != r.dst_ports[0].start) {
                range[pos++] = '-';
                format_uint(&range[pos], r.dst_ports[0].end);
            }
            write_padded(range, 13);
        } else {
            write_padded("any", 13);
        }
        write_padded(firewall_action_name(r.action), 8);
        write_padded_uint((uint32_t)r.match_count, 9);
        terminal_write_string(r.description);
        terminal_write_string("\n");
    }
    if (count == 0) terminal_write_string("No rules\n");
}

static void print_firewall_status(void) {
    terminal_write_string("\n=== FIREWALL STATUS ===\n");
    terminal_write_string("Status: ");
    terminal_write_string(firewall_is_enabled() ? "ENABLED\n" : "DISABLED\n");
    terminal_write_string("Default IN: ");
    terminal_write_string(firewall_action_name(firewall_get_default_policy(FIREWALL_DIR_IN)));
    terminal_write_string("  Default OUT: ");
    terminal_write_string(firewall_action_name(firewall_get_default_policy(FIREWALL_DIR_OUT)));
    terminal_write_string("\nRules: ");
    terminal_write_uint(firewall_get_rule_count());
    terminal_write_string("\n");
    firewall_stats_t* stats = firewall_get_statistics();
    if (!stats) return;
    terminal_write_string("Packets processed: ");
    terminal_write_uint((uint32_t)stats->packets_processed);
    terminal_write_string("  allowed: ");
    terminal_write_uint((uint32_t)stats->packets_allowed);
    terminal_write_string("  denied: ");
    terminal_write_uint((uint32_t)stats->packets_denied);
    terminal_write_string("  dropped: ");
    terminal_write_uint((uint32_t)stats->packets_dropped);
    terminal_write_string("\nActive connections: ");
    terminal_write_uint(stats->active_connections);
    terminal_write_string("  tracked: ");
    terminal_write_uint((uint32_t)stats->connections_tracked);
    terminal_write_string("  expired: ");
    terminal_write_uint((uint32_t)stats->connections_expired);
    terminal_write_string("\n");
}

// firewall add <in|out|both> <action> <proto> [port|lo-hi] [source a.b.c.d/prefix]
static void firewall_add_from_args(char* args[], int argc) {
    firewall_rule_t rule;
    for (uint32_t i = 0; i < sizeof(rule); i++) ((uint8_t*)&rule)[i] = 0;
    uint8_t protocol = 0;
    if (argc < 4 || !parse_fw_direction(args[1], &rule.direction) ||
        !parse_fw_action(args[2], &rule.action) || !parse_protocol(args[3], &protocol)) {
        terminal_write_string("Usage: firewall add <in|out|both> <allow|deny|drop|reject|log> <tcp|udp|icmp|any> [port|lo-hi] [source/prefix]\n");
        return;
    }
    rule.protocol = (firewall_protocol_t)protocol;
    if (argc >= 5) {
        if (!parse_port_range(args[4], &rule.dst_ports[0])) {
            terminal_write_string("Error: invalid port or range '");
            terminal_write_string(args[4]);
            terminal_write_string("'\n");
            return;
        }
        rule.dst_port_count = 1;
    }
    if (argc >= 6) {
        if (!parse_ip_prefix(args[5], &rule.src_ranges[0].network, &rule.src_ranges[0].netmask)) {
            terminal_write_string("Error: invalid address '");
            terminal_write_string(args[5]);
            terminal_write_string("'\n");
            return;
        }
        rule.src_range_count = 1;
    }
    string_copy(rule.description, "Added from shell");
    uint32_t id = firewall_add_rule(&rule);
    if (id == 0) {
        terminal_write_string("Error: rule table is full\n");
        return;
    }
    terminal_write_string("Rule ");
    terminal_write_uint(id);
    terminal_write_string(" added\n");
}

static bool command_firewall(char* args[], int argc) {
    initialize_security_subsystems();

    if (argc < 1) {
        terminal_write_string("\nUsage: firewall <command>\n");
        terminal_write_string("  enable | disable       Turn packet filtering on or off\n");
        terminal_write_string("  status                 Counters and default policies\n");
        terminal_write_string("  rules                  List rules in match order\n");
        terminal_write_string("  add <dir> <action> <proto> [port] [src/prefix]\n");
        terminal_write_string("  remove <id>            Delete a rule\n");
        terminal_write_string("  default <in|out> <action>\n");
        terminal_write_string("  log <0|1>              Print every rule match\n");
        terminal_write_string("  init                   Initialize network hardware\n");
        return true;
    }

    if (string_compare(args[0], "init") == 0) {
        initialize_network_security_subsystems();
    } else if (string_compare(args[0], "enable") == 0) {
        firewall_initialize();
    } else if (string_compare(args[0], "disable") == 0) {
        firewall_shutdown();
    } else if (string_compare(args[0], "status") == 0) {
        print_firewall_status();
    } else if (string_compare(args[0], "rules") == 0) {
        print_firewall_rules();
    } else if (string_compare(args[0], "add") == 0) {
        firewall_add_from_args(args, argc);
    } else if (string_compare(args[0], "remove") == 0 && argc >= 2) {
        uint32_t id = string_to_uint(args[1]);
        terminal_write_string(firewall_remove_rule(id) ? "Rule removed\n" : "Error: no rule with that ID\n");
    } else if (string_compare(args[0], "default") == 0 && argc >= 3) {
        firewall_direction_t direction;
        firewall_action_t action;
        if (!parse_fw_direction(args[1], &direction) || !parse_fw_action(args[2], &action) ||
            !firewall_set_default_policy(direction, action)) {
            terminal_write_string("Usage: firewall default <in|out|both> <allow|deny|drop|reject>\n");
        } else {
            terminal_write_string("Default policy updated\n");
        }
    } else if (string_compare(args[0], "log") == 0 && argc >= 2) {
        firewall_set_log_level((uint8_t)string_to_uint(args[1]));
        firewall_enable_connection_logging(string_to_uint(args[1]) > 0);
        terminal_write_string("Firewall logging updated\n");
    } else {
        terminal_write_string("Unknown firewall command. Use 'firewall' for usage.\n");
        return false;
    }
    return true;
}

static void print_ratelimit_rules(void) {
    static const char* scopes[] = {"global", "per-ip", "per-port", "per-conn", "per-subnet"};
    uint32_t count = rate_limiter_get_rule_count();
    terminal_write_string("\nID  Scope      Port   Rate   Burst  Limited  Description\n");
    for (uint32_t i = 0; i < count; i++) {
        rate_limit_rule_t r;
        if (!rate_limiter_get_rule_at(i, &r)) continue;
        write_padded_uint(r.rule_id, 4);
        write_padded(scopes[r.scope], 11);
        if (r.port_end) {
            write_padded_uint(r.port_start, 7);
        } else {
            write_padded("any", 7);
        }
        write_padded_uint(r.max_rate, 7);
        write_padded_uint(r.burst_size, 7);
        write_padded_uint((uint32_t)r.packets_limited, 9);
        terminal_write_string(r.description);
        terminal_write_string("\n");
    }
    if (count == 0) terminal_write_string("No rules\n");
}

static void print_ratelimit_status(void) {
    terminal_write_string("\n=== RATE LIMITING STATUS ===\n");
    terminal_write_string("Status: ");
    terminal_write_string(rate_limiter_is_enabled() ? "ENABLED\n" : "DISABLED\n");
    terminal_write_string("Rules: ");
    terminal_write_uint(rate_limiter_get_rule_count());
    terminal_write_string("\n");
    rate_limiter_stats_t* stats = rate_limiter_get_statistics();
    if (!stats) return;
    terminal_write_string("Total packets: ");
    terminal_write_uint((uint32_t)stats->total_packets);
    terminal_write_string("  allowed: ");
    terminal_write_uint((uint32_t)stats->packets_allowed);
    terminal_write_string("  limited: ");
    terminal_write_uint((uint32_t)stats->packets_limited);
    terminal_write_string("\nActive buckets: ");
    terminal_write_uint((uint32_t)stats->active_buckets);
    terminal_write_string("\n");
}

static void report_rule_added(const char* what, uint32_t rule_id) {
    if (rule_id == 0) {
        terminal_write_string("Error: rate must be above 0 and the rule table must have room\n");
        return;
    }
    terminal_write_string(what);
    terminal_write_string(" added (rule ID: ");
    terminal_write_uint(rule_id);
    terminal_write_string(")\n");
}

static bool command_ratelimit(char* args[], int argc) {
    if (argc < 1) {
        terminal_write_string("\nUsage: ratelimit <command>\n");
        terminal_write_string("  enable | disable       Turn rate limiting on or off\n");
        terminal_write_string("  status                 Counters\n");
        terminal_write_string("  rules                  List rules\n");
        terminal_write_string("  ddos                   Add the standard set of limits\n");
        terminal_write_string("  global <pps>           Limit all inbound packets\n");
        terminal_write_string("  perip <pps>            Limit each source address\n");
        terminal_write_string("  port <port> <pps>      Limit one destination port\n");
        terminal_write_string("  remove <id>            Delete a rule\n");
        return true;
    }

    if (string_compare(args[0], "enable") == 0) {
        rate_limiter_initialize();
    } else if (string_compare(args[0], "disable") == 0) {
        rate_limiter_shutdown();
    } else if (string_compare(args[0], "status") == 0 || string_compare(args[0], "stats") == 0) {
        print_ratelimit_status();
    } else if (string_compare(args[0], "rules") == 0) {
        print_ratelimit_rules();
    } else if (string_compare(args[0], "ddos") == 0) {
        terminal_write_string("Rules added: ");
        terminal_write_uint(rate_limiter_add_ddos_protection());
        terminal_write_string("\n");
    } else if (string_compare(args[0], "global") == 0 && argc >= 2) {
        uint32_t pps = string_to_uint(args[1]);
        report_rule_added("Global limit", rate_limiter_add_global_limit(pps, pps / 2));
    } else if (string_compare(args[0], "perip") == 0 && argc >= 2) {
        uint32_t pps = string_to_uint(args[1]);
        report_rule_added("Per-IP limit", rate_limiter_add_per_ip_limit(pps, pps / 2));
    } else if (string_compare(args[0], "port") == 0 && argc >= 3) {
        uint32_t pps = string_to_uint(args[2]);
        report_rule_added("Port limit", rate_limiter_add_port_limit((uint16_t)string_to_uint(args[1]), pps, pps / 2));
    } else if (string_compare(args[0], "remove") == 0 && argc >= 2) {
        uint32_t id = string_to_uint(args[1]);
        terminal_write_string(rate_limiter_remove_rule(id) ? "Rule removed\n" : "Error: no rule with that ID\n");
    } else {
        terminal_write_string("Unknown rate limit command. Use 'ratelimit' for help.\n");
        return false;
    }
    return true;
}

static void print_attestation(const secure_boot_attestation_t* a) {
    terminal_write_string("\n=== ATTESTATION REPORT ===\n");
    terminal_write_string("Boot State: ");
    terminal_set_color(a->boot_state == SECURE_BOOT_STATE_VERIFIED ? 10 : 12, 0);
    terminal_write_string(a->boot_state == SECURE_BOOT_STATE_VERIFIED ? "VERIFIED" : "NOT VERIFIED");
    terminal_set_color(7, 0);
    terminal_write_string("\nPlatform: ");
    terminal_write_string(a->platform_info);
    terminal_write_string("\nPolicy: ");
    terminal_write_string(a->boot_policy);
    terminal_write_string("\nMeasurements: ");
    terminal_write_uint(a->measurement_count);
    terminal_write_string("\nBoot time: ");
    terminal_write_uint(a->boot_time);
    terminal_write_string(" ms after power on  Report time: ");
    terminal_write_uint(a->report_time);
    terminal_write_string(" ms\nSignature: ");
    if (a->signature_size == 0) {
        terminal_write_string("unsigned, no platform key loaded\n");
    } else {
        terminal_write_string("HMAC-SHA256 ");
        terminal_write_string(secure_boot_verify_attestation(a) ? "verifies\n" : "DOES NOT verify\n");
    }
}

static void print_boot_state(void) {
    secure_boot_state_t state = secure_boot_get_state();
    terminal_write_string("Current boot state: ");
    switch (state) {
        case SECURE_BOOT_STATE_VERIFIED:
            terminal_set_color(10, 0);
            terminal_write_string("VERIFIED, kernel matches the build reference\n");
            break;
        case SECURE_BOOT_STATE_FAILED:
            terminal_set_color(12, 0);
            terminal_write_string("FAILED, kernel does not match the build reference\n");
            break;
        case SECURE_BOOT_STATE_COMPROMISED:
            terminal_set_color(12, 0);
            terminal_write_string("COMPROMISED, kernel changed after boot\n");
            break;
        default:
            terminal_set_color(14, 0);
            terminal_write_string("UNVERIFIED, no build reference embedded\n");
            break;
    }
    terminal_set_color(7, 0);
}

static bool command_secureboot(char* args[], int argc) {
    if (argc < 1) {
        terminal_write_string("\nUsage: secureboot <command>\n");
        terminal_write_string("  status          Boot state, policy and kernel hash\n");
        terminal_write_string("  measurements    Every measured component and its PCR\n");
        terminal_write_string("  test            Run the secure boot self-test\n");
        terminal_write_string("  attestation     Generate an attestation report\n");
        terminal_write_string("  verify          Show the boot verification result\n");
        terminal_write_string("  monitor [on|off] Check runtime integrity now, or every 30 s\n");
        terminal_write_string("  certs           List enrolled certificates\n");
        terminal_write_string("  policy <name>   Set permissive or strict, setup mode only\n");
        return true;
    }

    if (string_compare(args[0], "status") == 0) {
        secure_boot_print_status();
    } else if (string_compare(args[0], "measurements") == 0) {
        secure_boot_print_measurements();
    } else if (string_compare(args[0], "certs") == 0) {
        secure_boot_print_certificates();
    } else if (string_compare(args[0], "test") == 0) {
        bool ok = secure_boot_self_test();
        terminal_set_color(ok ? 10 : 12, 0);
        terminal_write_string(ok ? "SECURE BOOT SELF-TEST PASSED\n" : "SECURE BOOT SELF-TEST FAILED\n");
        terminal_set_color(7, 0);
    } else if (string_compare(args[0], "attestation") == 0) {
        secure_boot_attestation_t attestation;
        if (secure_boot_generate_attestation(&attestation)) {
            print_attestation(&attestation);
        } else {
            terminal_write_string("Error: secure boot is not initialized\n");
        }
    } else if (string_compare(args[0], "verify") == 0) {
        print_boot_state();
    } else if (string_compare(args[0], "monitor") == 0) {
        if (argc >= 2 && string_compare(args[1], "on") == 0) {
            terminal_write_string(secure_boot_start_runtime_monitoring() ? "Runtime monitoring on\n" : "Error: secure boot is not initialized\n");
        } else if (argc >= 2 && string_compare(args[1], "off") == 0) {
            secure_boot_stop_runtime_monitoring();
            terminal_write_string("Runtime monitoring off\n");
        } else {
            bool ok = secure_boot_check_runtime_integrity();
            terminal_set_color(ok ? 10 : 12, 0);
            terminal_write_string(ok ? "Runtime integrity check PASSED\n" : "Runtime integrity check FAILED\n");
            terminal_set_color(7, 0);
        }
    } else if (string_compare(args[0], "policy") == 0 && argc >= 2) {
        if (secure_boot_set_policy(args[1])) {
            terminal_write_string("Policy set\n");
        } else {
            terminal_write_string("Error: policy must be permissive or strict and setup mode must be on\n");
        }
    } else {
        terminal_write_string("Unknown secure boot command. Use 'secureboot' for help.\n");
        return false;
    }
    return true;
}

#define CRYPTO_RANDOM_MAX 64
#define CRYPTO_AES_TEXT_MAX 64

static void write_hex_bytes(const uint8_t* data, uint32_t length) {
    const char hex[] = "0123456789abcdef";
    for (uint32_t i = 0; i < length; i++) {
        terminal_write_char(hex[data[i] >> 4]);
        terminal_write_char(hex[data[i] & 0x0F]);
    }
}

// Encrypts with a fresh random key and IV, then decrypts to show the round trip
static void command_crypto_aes(const char* text) {
    uint8_t key[CRYPTO_AES_KEY_SIZE_256];
    uint8_t iv[CRYPTO_AES_BLOCK_SIZE];
    uint8_t plain[CRYPTO_AES_TEXT_MAX + CRYPTO_AES_BLOCK_SIZE] = {0};
    uint8_t cipher[sizeof(plain)];
    uint8_t back[sizeof(plain)];

    uint32_t length = string_length(text);
    if (length > CRYPTO_AES_TEXT_MAX) {
        terminal_write_string("Error: text is longer than 64 bytes\n");
        return;
    }
    for (uint32_t i = 0; i < length; i++) plain[i] = (uint8_t)text[i];
    uint32_t padded = crypto_padding_pkcs7_add(plain, length, sizeof(plain), CRYPTO_AES_BLOCK_SIZE);
    if (padded == 0 || !crypto_rng_get_bytes(key, sizeof(key)) || !crypto_rng_get_bytes(iv, sizeof(iv))) {
        terminal_write_string("Error: could not prepare key, IV or padding\n");
        return;
    }

    crypto_aes_context_t ctx;
    bool ok = crypto_aes_init(&ctx, CRYPTO_CIPHER_AES_256_CBC, key, iv) &&
              crypto_aes_encrypt(&ctx, plain, cipher, padded);
    crypto_aes_destroy(&ctx);
    ok = ok && crypto_aes_init(&ctx, CRYPTO_CIPHER_AES_256_CBC, key, iv) &&
         crypto_aes_decrypt(&ctx, cipher, back, padded);
    crypto_aes_destroy(&ctx);
    uint32_t back_length = padded;
    ok = ok && crypto_padding_pkcs7_remove(back, &back_length, CRYPTO_AES_BLOCK_SIZE);
    crypto_secure_zero(key, sizeof(key));

    if (!ok) {
        terminal_write_string("Error: AES-256-CBC encrypt or decrypt failed\n");
        return;
    }
    terminal_write_string("AES-256-CBC ciphertext: ");
    write_hex_bytes(cipher, padded);
    terminal_write_string("\nDecrypted: ");
    for (uint32_t i = 0; i < back_length; i++) terminal_write_char((char)back[i]);
    terminal_write_string("\nRound trip: ");
    terminal_write_string(back_length == length && crypto_secure_compare(back, plain, length) ? "match\n" : "MISMATCH\n");
}

static bool command_crypto(char* args[], int argc) {
    if (argc < 1) {
        terminal_write_string("\nUsage: crypto [test|hash|random|aes]\n");
        terminal_write_string("Cryptography commands:\n");
        terminal_write_string("  test            Run crypto self-test\n");
        terminal_write_string("  hash <text>     Compute SHA-256 hash\n");
        terminal_write_string("  random <bytes>  Generate random bytes\n");
        terminal_write_string("  aes <text>      Test AES encryption\n");
        return true;
    }

    if (string_compare(args[0], "test") == 0) {
        bool ok = crypto_self_test();
        terminal_set_color(ok ? 10 : 12, 0);
        terminal_write_string(ok ? "Cryptographic self-test PASSED\n" : "Cryptographic self-test FAILED\n");
        terminal_set_color(7, 0);
        return ok;
    }
    if (string_compare(args[0], "hash") == 0 && argc >= 2) {
        uint8_t hash[CRYPTO_SHA256_DIGEST_SIZE];
        if (!crypto_sha256((const uint8_t*)args[1], string_length(args[1]), hash)) {
            terminal_write_string("Error: SHA-256 failed, crypto is not initialized\n");
            return false;
        }
        terminal_write_string("SHA-256('");
        terminal_write_string(args[1]);
        terminal_write_string("') = ");
        write_hex_bytes(hash, sizeof(hash));
        terminal_write_string("\n");
        return true;
    }
    if (string_compare(args[0], "random") == 0 && argc >= 2) {
        uint32_t bytes = string_to_uint(args[1]);
        uint8_t random_data[CRYPTO_RANDOM_MAX];
        if (bytes == 0 || bytes > CRYPTO_RANDOM_MAX) {
            terminal_write_string("Invalid byte count (1-64)\n");
            return false;
        }
        if (!crypto_rng_get_bytes(random_data, bytes)) {
            terminal_write_string("Error: not enough entropy collected\n");
            return false;
        }
        terminal_write_string("Random bytes: ");
        write_hex_bytes(random_data, bytes);
        terminal_write_string("\n");
        return true;
    }
    if (string_compare(args[0], "aes") == 0 && argc >= 2) {
        command_crypto_aes(args[1]);
        return true;
    }
    terminal_write_string("Unknown crypto command. Use 'crypto' for help.\n");
    return false;
}

static void print_enabled(const char* label, bool enabled, uint32_t rules) {
    terminal_write_string(label);
    terminal_set_color(enabled ? 10 : 12, 0);
    terminal_write_string(enabled ? "ENABLED" : "DISABLED");
    terminal_set_color(7, 0);
    terminal_write_string(" (");
    terminal_write_uint(rules);
    terminal_write_string(" rules)\n");
}

static bool command_security_status(char* args[], int argc) {
    (void)args;
    (void)argc;
    terminal_write_string("\n=== APOLLO SECURITY STATUS ===\n");
    if (!security_initialized) {
        terminal_set_color(12, 0);
        terminal_write_string("Error: security subsystems did not initialize, crypto_initialize failed at boot\n");
        terminal_set_color(7, 0);
        return false;
    }

    secure_boot_state_t boot_state = secure_boot_get_state();
    terminal_write_string("Secure Boot: ");
    terminal_set_color(boot_state == SECURE_BOOT_STATE_VERIFIED ? 10 : 12, 0);
    terminal_write_string(boot_state == SECURE_BOOT_STATE_VERIFIED ? "VERIFIED" : "NOT VERIFIED");
    terminal_set_color(7, 0);
    terminal_write_string("\n");

    print_enabled("Firewall: ", firewall_is_enabled(), firewall_get_rule_count());
    print_enabled("Rate Limiting: ", rate_limiter_is_enabled(), rate_limiter_get_rule_count());

    tcp_statistics_t* tcp_stats = tcp_get_statistics();
    terminal_write_string("TCP Stack: ");
    if (tcp_stats) {
        terminal_write_string("initialized, connections: ");
        terminal_write_uint(tcp_stats->active_connections);
        terminal_write_string("\n");
    } else {
        terminal_write_string("not initialized\n");
    }

    uint8_t sources = crypto_get_entropy_sources();
    terminal_write_string("Cryptography: AES-128/256, SHA-256/512, HMAC, entropy from");
    if (sources & CRYPTO_ENTROPY_RDRAND) terminal_write_string(" RDRAND");
    if (sources & CRYPTO_ENTROPY_RDSEED) terminal_write_string(" RDSEED");
    if (sources & CRYPTO_ENTROPY_JITTER) terminal_write_string(" jitter");
    terminal_write_string("\n");
    return true;
}

bool command_aplay_list(void) {
    terminal_write_string("Apollo OS Audio Devices:\n");
    terminal_write_string("========================\n");

    uint32_t device_count = audio_get_device_count();

    if (device_count == 0) {
        terminal_write_string("No audio devices found.\n");
        return true;
    }

    for (uint32_t i = 0; i < device_count; i++) {
        char device_name[64];
        audio_device_caps_t caps;

        terminal_write_string("Device ");
        terminal_write_uint(i);
        terminal_write_string(": ");

        if (audio_get_device_info(i, device_name, sizeof(device_name))) {
            terminal_write_string(device_name);
        } else {
            terminal_write_string("Unknown Device");
        }
        terminal_write_string("\n");

        if (audio_get_device_capabilities(i, &caps)) {
            terminal_write_string("  Sample Rates: ");
            terminal_write_uint(caps.min_rate);
            terminal_write_string(" - ");
            terminal_write_uint(caps.max_rate);
            terminal_write_string(" Hz\n");

            terminal_write_string("  Channels: ");
            terminal_write_uint(caps.min_channels);
            terminal_write_string(" - ");
            terminal_write_uint(caps.max_channels);
            terminal_write_string("\n");
        }
        terminal_write_string("\n");
    }

    return true;
}

bool command_amixer(const char* args) {
    if (!args || strlen(args) == 0) {
        terminal_write_string("Apollo OS Audio Mixer:\n");
        terminal_write_string("=====================\n");
        terminal_write_string("Master Volume: ");
        terminal_write_uint(audio_get_master_volume());
        terminal_write_string("%");
        if (audio_get_mute()) {
            terminal_write_string(" [MUTED]");
        }
        terminal_write_string("\n");

        audio_system_stats_t stats;
        if (audio_get_system_stats(&stats)) {
            terminal_write_string("Active Playback Streams: ");
            terminal_write_uint(stats.active_playback);
            terminal_write_string("\n");
            terminal_write_string("Active Capture Streams: ");
            terminal_write_uint(stats.active_capture);
            terminal_write_string("\n");
        }
        return true;
    }

    if (command_starts_with(args, "set Master ")) {
        const char* vol_str = args + 11;  // Skip "set Master "
        uint32_t volume = 0;

        while (*vol_str >= '0' && *vol_str <= '9') {
            volume = volume * 10 + (*vol_str - '0');
            vol_str++;
        }

        if (volume > 100) volume = 100;

        if (audio_set_master_volume((uint8_t)volume)) {
            terminal_write_string("Volume set to ");
            terminal_write_uint(volume);
            terminal_write_string("%\n");
        } else {
            terminal_write_string("Failed to set volume\n");
        }
        return true;
    }

    if (command_starts_with(args, "mute")) {
        if (audio_set_mute(true)) {
            terminal_write_string("Audio muted\n");
        } else {
            terminal_write_string("Failed to mute audio\n");
        }
        return true;
    }

    if (command_starts_with(args, "unmute")) {
        if (audio_set_mute(false)) {
            terminal_write_string("Audio unmuted\n");
        } else {
            terminal_write_string("Failed to unmute audio\n");
        }
        return true;
    }

    terminal_write_string("Usage: amixer [set Master <volume>] [mute] [unmute]\n");
    return true;
}


bool command_aplay(const char* args) {
    if (!args || strlen(args) == 0) {
        terminal_write_string("Usage: aplay <filename.wav> [loop]\n");
        terminal_write_string("       aplay stop\n");
        terminal_write_string("       aplay pause\n");
        terminal_write_string("       aplay resume\n");
        terminal_write_string("       aplay status\n");
        return true;
    }

    if (command_starts_with(args, "stop")) {
        wav_player_t* player = get_shell_player();
        if (player) {
            wav_player_stop(player);
        } else {
            terminal_write_string("No audio playing\n");
        }
        return true;
    }

    if (command_starts_with(args, "pause")) {
        wav_player_t* player = get_shell_player();
        if (player && wav_player_get_state(player) == WAV_STATE_PLAYING) {
            wav_player_pause(player);
        } else {
            terminal_write_string("No audio playing\n");
        }
        return true;
    }

    if (command_starts_with(args, "resume")) {
        wav_player_t* player = get_shell_player();
        if (player && wav_player_get_state(player) == WAV_STATE_PAUSED) {
            wav_player_play(player);
        } else {
            terminal_write_string("No audio paused\n");
        }
        return true;
    }

    if (command_starts_with(args, "status")) {
        wav_player_t* player = get_shell_player();
        if (player) {
            wav_player_dump_info(player);
        } else {
            terminal_write_string("No audio player active\n");
        }
        return true;
    }

    char filename[256];
    bool loop = false;
    uint32_t pos = 0;

    while (args[pos] && args[pos] != ' ' && pos < 255) {
        filename[pos] = args[pos];
        pos++;
    }
    filename[pos] = '\0';

    while (args[pos] == ' ') pos++;
    if (command_starts_with(args + pos, "loop")) {
        loop = true;
    }

    clear_shell_player();

    wav_player_t* player = wav_player_create();
    if (!player) {
        terminal_write_string("Failed to create WAV player\n");
        return false;
    }

    set_shell_player(player);

    if (!wav_player_load_file(player, filename)) {
        terminal_write_string("Failed to load WAV file: ");
        terminal_write_string(filename);
        terminal_write_string("\n");
        clear_shell_player();
        return false;
    }

    wav_player_set_loop(player, loop);

    if (!wav_player_play(player)) {
        terminal_write_string("Failed to start playback\n");
        clear_shell_player();
        return false;
    }

    if (loop) {
        terminal_write_string("Playing ");
        terminal_write_string(filename);
        terminal_write_string(" (looped)\n");
        terminal_write_string("Use 'aplay stop' to stop playback\n");
    } else {
        terminal_write_string("Playing ");
        terminal_write_string(filename);
        terminal_write_string("\n");
    }

    return true;
}

bool command_audioinfo(void) {
    terminal_write_string("Apollo OS Audio System Information:\n");
    terminal_write_string("==================================\n");

    audio_dump_system_info();

    return true;
}

#define TONE_SAMPLE_RATE 48000
#define TONE_CHANNELS 2
#define TONE_BUFFER_FRAMES 8192
#define TONE_PERIOD_FRAMES 2048
#define TONE_CHUNK_FRAMES 512
#define TONE_AMPLITUDE_SHIFT 2
#define TONE_DRAIN_GRACE_MS 2000
#define SINE_QUARTER_STEPS 64
#define PHASE_INDEX_SHIFT 24

// sin(i * pi / 128) * 32767 for one quarter of a cycle
static const int16_t quarter_sine[SINE_QUARTER_STEPS + 1] = {
    0, 804, 1608, 2410, 3212, 4011, 4808, 5602, 6393, 7179, 7962, 8739, 9512, 10278, 11039, 11793,
    12539, 13279, 14010, 14732, 15446, 16151, 16846, 17530, 18204, 18868, 19519, 20159, 20787, 21403,
    22005, 22594, 23170, 23731, 24279, 24811, 25329, 25832, 26319, 26790, 27245, 27683, 28105, 28510,
    28898, 29268, 29621, 29956, 30273, 30571, 30852, 31113, 31356, 31580, 31785, 31971, 32137, 32285,
    32412, 32521, 32609, 32678, 32728, 32757, 32767
};

static int16_t sine_sample(uint32_t phase) {
    uint32_t index = phase >> PHASE_INDEX_SHIFT;
    uint32_t offset = index % SINE_QUARTER_STEPS;
    switch (index / SINE_QUARTER_STEPS) {
        case 0: return quarter_sine[offset];
        case 1: return quarter_sine[SINE_QUARTER_STEPS - offset];
        case 2: return (int16_t)-quarter_sine[offset];
        default: return (int16_t)-quarter_sine[SINE_QUARTER_STEPS - offset];
    }
}

static audio_device_t* open_tone_device(void) {
    audio_device_t* device = audio_device_open(0, AUDIO_DEVICE_PLAYBACK);
    if (!device) return NULL;
    audio_params_t params = {0};
    params.format = AUDIO_FORMAT_S16_LE;
    params.rate = TONE_SAMPLE_RATE;
    params.channels = TONE_CHANNELS;
    params.buffer_size = TONE_BUFFER_FRAMES;
    params.period_size = TONE_PERIOD_FRAMES;
    params.periods = TONE_BUFFER_FRAMES / TONE_PERIOD_FRAMES;
    if (!audio_device_set_params(device, &params) || !audio_device_prepare(device)) {
        audio_device_close(device);
        return NULL;
    }
    return device;
}

// Generates chunks while the hardware has room and returns the frames the DMA engine consumed
static uint32_t play_tone(audio_device_t* device, uint32_t frequency, uint32_t total_frames) {
    int16_t chunk[TONE_CHUNK_FRAMES * TONE_CHANNELS];
    uint32_t phase = 0;
    uint32_t step = (uint32_t)(((uint64_t)frequency << 32) / TONE_SAMPLE_RATE);
    uint32_t generated = 0;
    uint32_t deadline = get_system_time() + total_frames / (TONE_SAMPLE_RATE / 1000) + TONE_DRAIN_GRACE_MS;
    if (!audio_device_start(device)) return 0;

    while (get_system_time() < deadline) {
        uint32_t room = audio_device_available_frames(device);
        if (generated >= total_frames) {
            if (audio_device_delay_frames(device) == 0) break;
            continue;
        }
        if (room < TONE_CHUNK_FRAMES) continue;
        uint32_t frames = total_frames - generated;
        if (frames > TONE_CHUNK_FRAMES) frames = TONE_CHUNK_FRAMES;
        for (uint32_t i = 0; i < frames; i++) {
            int16_t sample = (int16_t)(sine_sample(phase) >> TONE_AMPLITUDE_SHIFT);
            chunk[i * TONE_CHANNELS] = sample;
            chunk[i * TONE_CHANNELS + 1] = sample;
            phase += step;
        }
        int32_t written = audio_device_write(device, chunk, frames);
        if (written < 0) break;
        generated += (uint32_t)written;
    }
    return generated - audio_device_delay_frames(device);
}

bool command_audiotone(const char* args) {
    if (!args || strlen(args) == 0) {
        terminal_write_string("Usage: audiotone <frequency> <duration_seconds>\n");
        terminal_write_string("Example: audiotone 440 3  (440 Hz for 3 seconds)\n");
        return true;
    }

    uint32_t frequency = 0;
    uint32_t duration = 1;
    const char* ptr = args;

    while (*ptr >= '0' && *ptr <= '9') {
        frequency = frequency * 10 + (*ptr - '0');
        ptr++;
    }

    while (*ptr == ' ') ptr++;

    if (*ptr >= '0' && *ptr <= '9') {
        duration = 0;
        while (*ptr >= '0' && *ptr <= '9') {
            duration = duration * 10 + (*ptr - '0');
            ptr++;
        }
    }

    if (frequency < 20 || frequency > 20000) {
        terminal_write_string("Frequency must be between 20 and 20000 Hz\n");
        return false;
    }

    if (duration > 30) {
        terminal_write_string("Duration limited to 30 seconds\n");
        duration = 30;
    }

    audio_device_t* device = open_tone_device();
    if (!device) {
        terminal_write_string("Error: no playback device, the HD Audio controller did not initialize\n");
        return false;
    }
    uint32_t total = duration * TONE_SAMPLE_RATE;
    terminal_write_string("Playing ");
    terminal_write_uint(frequency);
    terminal_write_string(" Hz for ");
    terminal_write_uint(duration);
    terminal_write_string(" s at 48000 Hz stereo\n");
    uint32_t played = play_tone(device, frequency, total);
    audio_device_stop(device);
    if (played != total) {
        terminal_write_string("Error: the controller consumed fewer frames than were queued\n");
        hda_dump_stream_info(device->controller, device->stream_id);
        hda_dump_codec_info(device->controller, 0);
    }
    audio_device_close(device);

    terminal_write_string("Played ");
    terminal_write_uint(played);
    terminal_write_string(" of ");
    terminal_write_uint(total);
    terminal_write_string(" frames\n");
    return played == total;
}

bool command_audiotest(void) {
    terminal_write_string("Apollo OS Audio System Test:\n");
    terminal_write_string("============================\n");

    if (!audio_subsystem_self_test()) {
        terminal_write_string("Audio subsystem self-test failed\n");
        return false;
    }

    terminal_write_string("Audio system test complete\n");
    return true;
}

#define PCI_CLASS_MULTIMEDIA 0x04
#define PCI_SUBCLASS_HDA 0x03
#define REALTEK_VENDOR_ID 0x10EC
#define RTL8139_PCI_DEVICE_ID 0x8139
#define DRIVERINFO_MAX_DEVICES 64
#define NETWORKFIX_DHCP_WAIT_MS 15000
#define RX_TEST_MS 3000

static void write_hex_digits(uint32_t value, uint32_t digits) {
    const char hex[] = "0123456789ABCDEF";
    while (digits > 0) {
        digits--;
        terminal_write_char(hex[(value >> (digits * 4)) & 0x0F]);
    }
}

static void write_pci_location(const pci_device_t* dev) {
    write_hex_digits(dev->bus, 2);
    terminal_write_char(':');
    write_hex_digits(dev->device, 2);
    terminal_write_char('.');
    terminal_write_uint(dev->function);
}

static const char* interface_state_name(net_interface_state_t state) {
    switch (state) {
        case NET_INTERFACE_DOWN: return "DOWN";
        case NET_INTERFACE_UP: return "UP";
        case NET_INTERFACE_LINK_DOWN: return "LINK DOWN";
        case NET_INTERFACE_LINK_UP: return "LINK UP";
    }
    return "UNKNOWN";
}

static void print_interface_binding(network_interface_t* iface) {
    if (!iface) {
        terminal_write_string("bound, no interface registered");
        return;
    }
    terminal_write_string("bound to ");
    terminal_write_string(iface->name);
    terminal_write_string(", ");
    terminal_write_string(interface_state_name(iface->state));
}

// Reports the driver Apollo has for a device and what that driver does right now
static void print_driver_status(const pci_device_t* dev) {
    if (dev->vendor_id == REALTEK_VENDOR_ID && dev->device_id == RTL8139_PCI_DEVICE_ID) {
        rtl8139_device_t* nic = rtl8139_find_device(dev->bus, dev->device, dev->function);
        terminal_write_string("rtl8139   ");
        if (nic) {
            print_interface_binding(nic->interface);
            terminal_write_string(", transmit and receive");
        } else {
            terminal_write_string("not initialized");
        }
        return;
    }
    if (intel_e1000_supports(dev->vendor_id, dev->device_id)) {
        intel_e1000_device_t* nic = intel_e1000_find_device(dev->bus, dev->device, dev->function);
        terminal_write_string("e1000     ");
        if (nic) {
            print_interface_binding(nic->interface);
            terminal_write_string(", transmit and receive");
        } else {
            terminal_write_string("not initialized");
        }
        return;
    }
    if (dev->class_code == PCI_CLASS_MULTIMEDIA && dev->subclass == PCI_SUBCLASS_HDA) {
        terminal_write_string("hda       ");
        hda_controller_t* hda = g_hda_controller;
        if (hda && hda->is_initialized && hda->bus == dev->bus &&
            hda->device == dev->device && hda->function == dev->function) {
            terminal_write_string("bound, codecs: ");
            terminal_write_uint(hda->num_codecs);
        } else {
            terminal_write_string("not initialized");
        }
        return;
    }
    terminal_write_string("none");
}

static void command_driverinfo(void) {
    pci_device_t devices[DRIVERINFO_MAX_DEVICES];
    uint32_t count = pci_enumerate(devices, DRIVERINFO_MAX_DEVICES);
    uint32_t shown = 0;

    terminal_write_string("\nLocation  ID         Driver    Status\n");
    for (uint32_t i = 0; i < count; i++) {
        const pci_device_t* dev = &devices[i];
        if (dev->class_code != PCI_CLASS_NETWORK && dev->class_code != PCI_CLASS_MULTIMEDIA) {
            continue;
        }
        write_pci_location(dev);
        terminal_write_string("   ");
        write_hex_digits(dev->vendor_id, 4);
        terminal_write_char(':');
        write_hex_digits(dev->device_id, 4);
        terminal_write_string("  ");
        print_driver_status(dev);
        terminal_write_string("\n");
        const char* name = pci_device_name(dev->vendor_id, dev->device_id);
        if (name) {
            terminal_write_string("          ");
            terminal_write_string(name);
            terminal_write_string("\n");
        }
        shown++;
    }
    if (shown == 0) {
        terminal_write_string("No network or audio devices on the PCI bus\n");
    }
}

static void networkfix_step(const char* name, bool ok) {
    terminal_write_string(name);
    terminal_set_color(ok ? 10 : 12, 0);
    terminal_write_string(ok ? " ok\n" : " failed\n");
    terminal_set_color(7, 0);
}

static bool networkfix_wait_for_address(network_interface_t* iface) {
    uint32_t start = get_system_time();
    while (get_system_time() - start < NETWORKFIX_DHCP_WAIT_MS) {
        network_poll();
        if (iface->ip_addr.addr != 0) return true;
    }
    return false;
}

// Runs each bring up step in order and stops at the first one that fails
static void command_networkfix(void) {
    pci_device_t devices[DRIVERINFO_MAX_DEVICES];
    uint32_t count = pci_enumerate(devices, DRIVERINFO_MAX_DEVICES);
    uint32_t nics = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (devices[i].class_code == PCI_CLASS_NETWORK) nics++;
    }
    networkfix_step("\n1. Network device on PCI bus:", nics > 0);
    if (nics == 0) {
        print_network_error("no PCI device with class 02 (network)", 0, NULL);
        print_qemu_network_hint();
        return;
    }

    if (network_manager_get_interface_count() == 0) {
        network_manager_initialize_hardware();
    }
    network_interface_t* interfaces[NET_MAX_INTERFACES];
    uint32_t if_count = network_interface_list_all(interfaces, NET_MAX_INTERFACES);
    networkfix_step("2. Driver registered an interface:", if_count > 0);
    if (if_count == 0) {
        print_network_error("network devices found: ", nics, ", interfaces registered: 0");
        terminal_write_string("  Run driverinfo to see which driver each device has\n");
        return;
    }
    network_interface_t* iface = interfaces[0];

    if (iface->state != NET_INTERFACE_UP) {
        network_interface_bring_up(iface->interface_id);
    }
    networkfix_step("3. Interface is UP:", iface->state == NET_INTERFACE_UP);
    if (iface->state != NET_INTERFACE_UP) {
        print_network_error("interface state ", iface->state, "");
        return;
    }

    if (iface->ip_addr.addr == 0) {
        dhcp_start_on_interface(iface);
        networkfix_wait_for_address(iface);
    }
    networkfix_step("4. IP address assigned:", iface->ip_addr.addr != 0);
    if (iface->ip_addr.addr == 0) {
        print_dhcp_failure(iface);
        print_qemu_network_hint();
        return;
    }

    mac_address_t gateway_mac;
    bool gateway_ok = iface->gateway.addr != 0 && arp_resolve_ip(iface, &iface->gateway, &gateway_mac);
    networkfix_step("5. Gateway answers ARP:", gateway_ok);
    if (!gateway_ok) {
        if (iface->gateway.addr == 0) {
            print_network_error("no gateway configured", 0, NULL);
        } else {
            print_arp_failure(iface, &iface->gateway);
        }
        print_qemu_network_hint();
    }
}

static bool is_native_program(const char* path) {
    program_format_t format = program_detect(path);
    return format == PROGRAM_FORMAT_ELF || format == PROGRAM_FORMAT_PE || format == PROGRAM_FORMAT_BIN;
}

static void run_native_program(int argc, char* argv[]) {
    char error[PROGRAM_ERROR_LENGTH];
    int64_t exit_code = 0;
    terminal_write_string("\n");
    if (!program_run(argv[0], argc, argv, &exit_code, error)) {
        terminal_set_color(12, 0);
        terminal_write_string("Error: ");
        terminal_write_string(error);
        terminal_write_string("\n");
        terminal_set_color(7, 0);
        return;
    }
    terminal_write_string("\nExit code: ");
    terminal_write_int((int32_t)exit_code);
    // Windows status codes read better in hex, 0xC0000005 rather than -1073741819
    if (program.format == PROGRAM_FORMAT_PE && (int32_t)exit_code < 0) {
        terminal_write_string(" (");
        terminal_write_hex((uint32_t)exit_code);
        terminal_write_string(")");
    }
    terminal_write_string("\n");
}

#define PS_MAX_TASKS 32

// Kernel tasks are main loop stages, CPU time is measured with the TSC around each stage
static void command_ps(void) {
    process_t tasks[PS_MAX_TASKS];
    uint32_t count = process_list(tasks, PS_MAX_TASKS);
    terminal_write_string("\nPID  STATE    TYPE    CPU ms    MEMORY    NAME\n");
    for (uint32_t i = 0; i < count; i++) {
        write_padded_uint(tasks[i].pid, 5);
        write_padded(process_get_state_string(tasks[i].state), 9);
        write_padded(process_get_type_string(tasks[i].type), 8);
        write_padded_uint(tasks[i].cpu_time, 10);
        if (tasks[i].memory_usage) {
            char size[16];
            uint32_t pos = format_uint(size, tasks[i].memory_usage / 1024);
            size[pos++] = 'K';
            size[pos] = '\0';
            write_padded(size, 10);
        } else {
            write_padded("-", 10);
        }
        terminal_write_string(tasks[i].name);
        terminal_write_string("\n");
    }
    process_stats_t stats;
    if (process_get_stats(&stats)) {
        terminal_write_string("Tasks: ");
        terminal_write_uint(stats.total_processes);
        terminal_write_string("  suspended: ");
        terminal_write_uint(stats.blocked_processes);
        terminal_write_string("  task switches: ");
        terminal_write_uint(stats.context_switches);
        terminal_write_string("\n");
    }
}

#define KBC_STATUS_PORT 0x64
#define KBC_INPUT_FULL 0x02
#define KBC_PULSE_RESET 0xFE

// Pulses the reset line through the keyboard controller, a triple fault is the fallback
static void reboot_machine(void) {
    while (inb(KBC_STATUS_PORT) & KBC_INPUT_FULL) {}
    outb(KBC_STATUS_PORT, KBC_PULSE_RESET);
    time_keeper_delay_ms(100);
    struct __attribute__((packed)) { uint16_t limit; uint64_t base; } empty_idt = {0, 0};
    __asm__ volatile("lidt %0; int $3" : : "m"(empty_idt));
}

static void initialize_security_subsystems(void) {
    if (security_initialized) return;

    terminal_write_string("Initializing security subsystems...\n");

    bool crypto_ok = false, audit_ok = false, boot_ok = false;

    terminal_write_string("- Initializing cryptography...\n");
    crypto_ok = crypto_initialize();
    if (!crypto_ok) {
        terminal_set_color(12, 0);
        terminal_write_string("ERROR: Failed to initialize cryptography\n");
        terminal_set_color(7, 0);
        return;
    }
    terminal_write_string("  Cryptography: OK\n");

    terminal_write_string("- Initializing secure boot...\n");
    boot_ok = secure_boot_early_init();
    if (!boot_ok) {
        terminal_set_color(12, 0);
        terminal_write_string("ERROR: Failed to initialize secure boot\n");
        terminal_set_color(7, 0);
    } else {
        terminal_write_string("  Secure boot: OK\n");
    }

    terminal_write_string("- Initializing security audit...\n");
    audit_ok = security_audit_initialize();
    if (!audit_ok) {
        terminal_set_color(12, 0);
        terminal_write_string("ERROR: Failed to initialize security audit\n");
        terminal_set_color(7, 0);
    } else {
        terminal_write_string("  Security audit: OK\n");
    }

    if (boot_ok) {
        terminal_write_string("- Completing secure boot setup...\n");
        if (!secure_boot_initialize()) {
            terminal_set_color(12, 0);
            terminal_write_string("ERROR: Failed to complete secure boot initialization\n");
            terminal_set_color(7, 0);
        } else {
            terminal_write_string("  Secure boot complete: OK\n");
        }
    }

    security_initialized = true;
    terminal_set_color(10, 0);
    terminal_write_string("Core security subsystems initialization complete\n");
    terminal_set_color(7, 0);
}

static void initialize_network_security_subsystems(void) {
    if (network_init_attempted) {
        terminal_write_string("Network security initialization already attempted\n");
        return;
    }

    network_init_attempted = true;
    terminal_write_string("Initializing network security components...\n");

    bool tcp_ok = false, firewall_ok = false, ratelimit_ok = false;

    terminal_write_string("- Attempting TCP stack initialization...\n");
    tcp_ok = tcp_initialize();
    if (!tcp_ok) {
        terminal_set_color(14, 0);
        terminal_write_string("WARNING: TCP stack initialization failed - continuing\n");
        terminal_set_color(7, 0);
    } else {
        terminal_write_string("  TCP stack: OK\n");
    }

    terminal_write_string("- Attempting firewall initialization...\n");
    firewall_ok = firewall_initialize();
    if (!firewall_ok) {
        terminal_set_color(14, 0);
        terminal_write_string("WARNING: Firewall initialization failed - software mode\n");
        terminal_set_color(7, 0);
    } else {
        terminal_write_string("  Firewall: OK\n");
    }

    terminal_write_string("- Attempting rate limiter initialization...\n");
    ratelimit_ok = rate_limiter_initialize();
    if (!ratelimit_ok) {
        terminal_set_color(14, 0);
        terminal_write_string("WARNING: Rate limiter initialization failed\n");
        terminal_set_color(7, 0);
    } else {
        terminal_write_string("  Rate limiter: OK\n");
    }

    if (tcp_ok || firewall_ok || ratelimit_ok) {
        terminal_set_color(10, 0);
        terminal_write_string("Network security initialization completed (partial)\n");
        terminal_set_color(7, 0);
    } else {
        terminal_set_color(12, 0);
        terminal_write_string("ERROR: All network security components failed\n");
        terminal_set_color(7, 0);
    }
}

void terminal_write_decimal(uint32_t value) {
    char buffer[12];
    int i = 0;

    if (value == 0) {
        terminal_write_char('0');
        return;
    }

    while (value > 0) {
        buffer[i++] = '0' + (value % 10);
        value /= 10;
    }

    for (int j = i - 1; j >= 0; j--) {
        terminal_write_char(buffer[j]);
    }
}

void terminal_write_hex_byte(uint8_t value) {
    char hex_chars[] = "0123456789ABCDEF";
    terminal_write_char(hex_chars[(value >> 4) & 0x0F]);
    terminal_write_char(hex_chars[value & 0x0F]);
}

network_interface_t* network_get_interface(int index) {
    if (index < 0) return NULL;

    return network_interface_get_by_id(index + 1);
}

static void execute_command(const char* input) {
    char args[MAX_ARGUMENTS][MAX_COMMAND_LENGTH];
    uint32_t argc = parse_arguments(input, args);

    if (argc == 0) return;

    add_command_to_history(input);

    // Handlers take pointers, subcommand handlers start after the command name
    char* arg_ptrs[MAX_ARGUMENTS];
    for (uint32_t i = 0; i < argc; i++) {
        arg_ptrs[i] = args[i];
    }
    char** sub_args = arg_ptrs + 1;
    int sub_argc = (int)argc - 1;

    if (string_compare(args[0], "help") == 0) {
        terminal_write_string("\nApollo Shell - Command Reference\n");
        terminal_write_string("==========================================\n\n");

        terminal_set_color(14, 0);
        terminal_write_string("File System Commands:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  ls, dir      - List directory contents\n");
        terminal_write_string("  cd <path>    - Change directory\n");
        terminal_write_string("  pwd          - Print working directory\n");
        terminal_write_string("  mkdir <dir>  - Create directory\n");
        terminal_write_string("  rmdir <dir>  - Remove directory\n");
        terminal_write_string("  rm <file>    - Delete file\n");
        terminal_write_string("  cp <s> <d>   - Copy file\n");
        terminal_write_string("  mv <s> <d>   - Move/rename file\n");
        terminal_write_string("  cat <file>   - Display file contents\n");
        terminal_write_string("  touch <file> - Create empty file\n");
        terminal_write_string("  find <pat>   - Search for files\n");
        terminal_write_string("  tree         - Directory structure\n");
        terminal_write_string("  grep <p> <f> - Search text in files\n");
        terminal_write_string("  exec <file>  - Execute a compiled bianary\n\n");

        terminal_set_color(12, 0);
        terminal_write_string("System Information:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  sysinfo      - Complete system info\n");
        terminal_write_string("  meminfo      - Memory usage statistics\n");
        terminal_write_string("  df           - Filesystem usage\n");
        terminal_write_string("  ps           - Process list\n");
        terminal_write_string("  whoami       - User information\n");
        terminal_write_string("  date         - Current date/time\n");
        terminal_write_string("  uptime       - System uptime\n\n");

        terminal_set_color(10, 0);
        terminal_write_string("Utilities:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  calc <expr>  - Calculator (e.g., calc 15 + 25)\n");
        terminal_write_string("  echo <text>  - Display text\n");
        terminal_write_string("  history      - Command history\n");
        terminal_write_string("  clear        - Clear screen\n");
        terminal_write_string("  edit <file>  - Text editor\n");
        terminal_write_string("  palette      - Color palette demo\n\n");

        terminal_set_color(9, 0);
        terminal_write_string("Network Commands:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  ifconfig     - Show/configure network interfaces\n");
        terminal_write_string("  ping <h> [n] - Send n echo requests\n");
        terminal_write_string("  nslookup <h> - DNS lookup for hostname\n");
        terminal_write_string("  netstat      - Show network statistics\n");
        terminal_write_string("  dhcp <iface> - Enable DHCP on interface\n");
        terminal_write_string("  wget <url>   - Download data from URL\n");
        terminal_write_string("  netstatus    - Show detailed network status\n");
        terminal_write_string("  nettest      - Network diagnostics and testing\n");
        terminal_write_string("  netinfo      - Complete network information\n");
        terminal_write_string("  rawsend <msg>- Send raw UDP test packet\n");
        terminal_write_string("  arp <cmd>    - ARP table management\n");
        terminal_write_string("  arpping <ip> - Sends ARP request to populate ARP table\n");
        terminal_write_string("  route <cmd>  - Routing table management\n");
        terminal_write_string("  traceroute   - Trace route to destination\n");
        terminal_write_string("  telnet <h>   - Interactive TCP session, Esc closes\n");
        terminal_write_string("  tcpdump [n]  - Show captured frames\n");
        terminal_write_string("  listen <p>   - TCP echo service on a port\n");
        terminal_write_string("  pcilist      - List all PCI devices\n");
        terminal_write_string("  netdetect    - Detect network hardware\n");
        terminal_write_string("  hwdiag       - Complete hardware diagnostic\n");
        terminal_write_string("  driverinfo   - Show driver implementation status\n");
        terminal_write_string("  networkfix   - Bring up networking step by step\n\n");

        terminal_set_color(13, 0);  // Magenta
        terminal_write_string("\nSecurity Commands:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  security     - Show overall security status\n");
        terminal_write_string("  secaudit     - Run security audit\n");
        terminal_write_string("  firewall     - Manage stateful firewall\n");
        terminal_write_string("  ratelimit    - Configure DDoS protection\n");
        terminal_write_string("  secureboot   - Secure boot management\n");
        terminal_write_string("  crypto       - Cryptographic operations\n\n");

        terminal_set_color(14, 0);
        terminal_write_string("\nAudio Commands:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  aplay <file> - Play WAV audio files\n");
        terminal_write_string("  amixer       - Audio mixer control\n");
        terminal_write_string("  audioinfo    - Audio system information\n");
        terminal_write_string("  audiotone    - Generate test tones\n");
        terminal_write_string("  audiotest    - Audio system test\n");
        terminal_write_string("  lsaudio      - List audio devices\n\n");

        terminal_set_color(19, 0);
        terminal_write_string("Compiler commands:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  acc -help    - Show compiler's help dialog\n");
        terminal_write_string("  abuild       - Create a build file\n\n");

        terminal_set_color(11, 0);
        terminal_write_string("System Control:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  reboot       - Restart system\n");
        terminal_write_string("  shutdown     - Halt system\n\n");

        terminal_set_color(8, 0);
        terminal_write_string("Navigation:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  Ctrl+Up/Down - Scroll through terminal output\n");
        terminal_write_string("  Ctrl+Home    - Scroll to top\n");
        terminal_write_string("  Ctrl+End     - Scroll to bottom\n");
        terminal_write_string("  Up/Down      - Browse command history\n\n");

    } else if (string_compare(args[0], "clear") == 0) {
        terminal_clear();

    } else if (string_compare(args[0], "ls") == 0 || string_compare(args[0], "dir") == 0) {
        const char* path = (argc > 1) ? args[1] : NULL;
        fs_dir_entry_t entries[64];
        uint32_t count = filesystem_list_directory(path, entries, 64);

        terminal_write_string("\n");
        if (count == 0) {
            terminal_write_string("Directory is empty or does not exist.\n");
        } else {
            char current_dir[FS_MAX_PATH_LENGTH];
            if (filesystem_get_current_directory(current_dir, sizeof(current_dir))) {
                terminal_set_color(11, 0);
                terminal_write_string("Directory: ");
                terminal_write_string(current_dir);
                terminal_write_string("\n\n");
                terminal_set_color(7, 0);
            }

            uint32_t total_files = 0, total_dirs = 0, total_size = 0;

            for (uint32_t i = 0; i < count; i++) {
                if (entries[i].type == FS_TYPE_DIRECTORY) {
                    terminal_set_color(12, 0);
                    terminal_write_string("d");
                    total_dirs++;
                } else {
                    terminal_set_color(10, 0);
                    terminal_write_string("-");
                    total_files++;
                    total_size += entries[i].size;
                }

                terminal_set_color(8, 0);
                terminal_write_string((entries[i].permissions & FS_PERM_READ) ? "r" : "-");
                terminal_write_string((entries[i].permissions & FS_PERM_WRITE) ? "w" : "-");
                terminal_write_string((entries[i].permissions & FS_PERM_EXECUTE) ? "x" : "-");
                terminal_write_string(" ");

                terminal_set_color(14, 0);
                if (entries[i].type == FS_TYPE_FILE) {
                    if (entries[i].size < 10) terminal_write_string("     ");
                    else if (entries[i].size < 100) terminal_write_string("    ");
                    else if (entries[i].size < 1000) terminal_write_string("   ");
                    else if (entries[i].size < 10000) terminal_write_string("  ");
                    else if (entries[i].size < 100000) terminal_write_string(" ");
                    terminal_write_uint(entries[i].size);
                } else {
                    terminal_write_string("      -");
                }
                terminal_write_string(" ");

                terminal_set_color(7, 0);
                terminal_write_string(entries[i].name);
                terminal_write_string("\n");
            }

            terminal_write_string("\n");
            terminal_set_color(8, 0);
            terminal_write_string("Total: ");
            terminal_write_uint(total_dirs);
            terminal_write_string(" directories, ");
            terminal_write_uint(total_files);
            terminal_write_string(" files (");
            terminal_write_uint(total_size);
            terminal_write_string(" bytes)\n");
            terminal_set_color(7, 0);
        }

    } else if (string_compare(args[0], "cd") == 0) {
        const char* path = (argc > 1) ? args[1] : "/";
        char old_dir[FS_MAX_PATH_LENGTH];
        filesystem_get_current_directory(old_dir, sizeof(old_dir));

        if (filesystem_change_directory(path)) {
            char current_dir[FS_MAX_PATH_LENGTH];
            if (filesystem_get_current_directory(current_dir, sizeof(current_dir))) {
                terminal_write_string("\nChanged directory:\n");
                terminal_set_color(8, 0);
                terminal_write_string("  From: ");
                terminal_write_string(old_dir);
                terminal_write_string("\n");
                terminal_set_color(11, 0);
                terminal_write_string("  To:   ");
                terminal_write_string(current_dir);
                terminal_write_string("\n");
                terminal_set_color(7, 0);
            }
        } else {
            terminal_write_string("\nError: Cannot change to directory '");
            terminal_write_string(path);
            terminal_write_string("'\n");
        }

    } else if (string_compare(args[0], "pwd") == 0) {
        char current_dir[FS_MAX_PATH_LENGTH];
        if (filesystem_get_current_directory(current_dir, sizeof(current_dir))) {
            terminal_write_string("\n");
            terminal_set_color(11, 0);
            terminal_write_string(current_dir);
            terminal_set_color(7, 0);
            terminal_write_string("\n");
        } else {
            terminal_write_string("\nError: Cannot determine current directory.\n");
        }

    } else if (string_compare(args[0], "mkdir") == 0) {
        if (argc < 2) {
            terminal_write_string("\nUsage: mkdir <directory>\n");
        } else {
            if (filesystem_create_directory(args[1])) {
                terminal_write_string("\nDirectory '");
                terminal_write_string(args[1]);
                terminal_write_string("' created successfully.\n");
            } else {
                terminal_write_string("\nError: Cannot create directory '");
                terminal_write_string(args[1]);
                terminal_write_string("'\n");
            }
        }

    } else if (string_compare(args[0], "rmdir") == 0) {
        if (argc < 2) {
            terminal_write_string("\nUsage: rmdir <directory>\n");
        } else {
            if (filesystem_remove_directory(args[1])) {
                terminal_write_string("\nDirectory '");
                terminal_write_string(args[1]);
                terminal_write_string("' removed successfully.\n");
            } else {
                terminal_write_string("\nError: Cannot remove directory '");
                terminal_write_string(args[1]);
                terminal_write_string("': it does not exist, is not empty, is not a directory or contains the current directory\n");
            }
        }

    } else if (string_compare(args[0], "rm") == 0 || string_compare(args[0], "del") == 0) {
        if (argc < 2) {
            terminal_write_string("\nUsage: rm <file>\n");
        } else {
            if (filesystem_delete_file(args[1])) {
                terminal_write_string("\nFile '");
                terminal_write_string(args[1]);
                terminal_write_string("' deleted successfully.\n");
            } else {
                terminal_write_string("\nError: Cannot delete file '");
                terminal_write_string(args[1]);
                terminal_write_string("'\n");
            }
        }

    } else if (string_compare(args[0], "cp") == 0 || string_compare(args[0], "copy") == 0) {
        if (argc < 3) {
            terminal_write_string("\nUsage: cp <source> <destination>\n");
        } else {
            if (filesystem_copy_file(args[1], args[2])) {
                terminal_write_string("\nFile copied from '");
                terminal_write_string(args[1]);
                terminal_write_string("' to '");
                terminal_write_string(args[2]);
                terminal_write_string("'\n");
            } else {
                terminal_write_string("\nError: Cannot copy file\n");
            }
        }

    } else if (string_compare(args[0], "mv") == 0 || string_compare(args[0], "move") == 0) {
        if (argc < 3) {
            terminal_write_string("\nUsage: mv <source> <destination>\n");
        } else {
            if (filesystem_move_file(args[1], args[2])) {
                terminal_write_string("\nFile moved from '");
                terminal_write_string(args[1]);
                terminal_write_string("' to '");
                terminal_write_string(args[2]);
                terminal_write_string("'\n");
            } else {
                terminal_write_string("\nError: Cannot move file\n");
            }
        }

    } else if (string_compare(args[0], "touch") == 0) {
        if (argc < 2) {
            terminal_write_string("\nUsage: touch <filename>\n");
        } else {
            if (filesystem_create_file(args[1])) {
                terminal_write_string("\nFile '");
                terminal_write_string(args[1]);
                terminal_write_string("' created successfully.\n");
            } else {
                terminal_write_string("\nError: Cannot create file '");
                terminal_write_string(args[1]);
                terminal_write_string("'\n");
            }
        }

    } else if (string_compare(args[0], "cat") == 0 || string_compare(args[0], "type") == 0) {
        if (argc < 2) {
            terminal_write_string("\nUsage: cat <filename>\n");
        } else {
            if (!filesystem_file_exists(args[1])) {
                terminal_write_string("\nError: File '");
                terminal_write_string(args[1]);
                terminal_write_string("' does not exist.\n");
            } else {
                fs_file_handle_t* handle = filesystem_open_file(args[1], false);
                if (!handle) {
                    terminal_write_string("\nError: Cannot open file.\n");
                } else {
                    fs_file_info_t info;
                    if (filesystem_get_file_info(args[1], &info)) {
                        terminal_write_string("\n");
                        terminal_set_color(8, 0);
                        terminal_write_string("--- ");
                        terminal_write_string(args[1]);
                        terminal_write_string(" (");
                        terminal_write_uint(info.size);
                        terminal_write_string(" bytes) ---\n");
                        terminal_set_color(7, 0);
                    }

                    char buffer[512];
                    uint32_t bytes_read;
                    uint32_t total_bytes = 0;
                    uint32_t line_count = 1;

                    while ((bytes_read = filesystem_read_file(handle, buffer, sizeof(buffer) - 1)) > 0) {
                        buffer[bytes_read] = '\0';
                        for (uint32_t i = 0; i < bytes_read; i++) {
                            if (buffer[i] == '\n') line_count++;
                        }
                        terminal_write_string(buffer);
                        total_bytes += bytes_read;
                    }

                    filesystem_close_file(handle);
                    terminal_write_string("\n");
                    terminal_set_color(8, 0);
                    terminal_write_string("--- End (");
                    terminal_write_uint(total_bytes);
                    terminal_write_string(" bytes, ");
                    terminal_write_uint(line_count);
                    terminal_write_string(" lines) ---\n");
                    terminal_set_color(7, 0);
                }
            }
        }

    } else if (string_compare(args[0], "find") == 0) {
        if (argc < 2) {
            terminal_write_string("\nUsage: find <pattern>\n");
        } else {
            terminal_write_string("\nSearching for files containing '");
            terminal_write_string(args[1]);
            terminal_write_string("':\n\n");

            fs_dir_entry_t entries[64];
            uint32_t count = filesystem_list_directory(NULL, entries, 64);
            uint32_t found = 0;

            for (uint32_t i = 0; i < count; i++) {
                if (string_contains(entries[i].name, args[1])) {
                    terminal_set_color(11, 0);
                    terminal_write_string("  ");
                    terminal_write_string(entries[i].name);
                    terminal_set_color(7, 0);
                    if (entries[i].type == FS_TYPE_DIRECTORY) {
                        terminal_write_string(" (directory)");
                    } else {
                        terminal_write_string(" (");
                        terminal_write_uint(entries[i].size);
                        terminal_write_string(" bytes)");
                    }
                    terminal_write_string("\n");
                    found++;
                }
            }

            if (found == 0) {
                terminal_write_string("No files found matching pattern.\n");
            } else {
                terminal_write_string("\nFound ");
                terminal_write_uint(found);
                terminal_write_string(" matching files.\n");
            }
        }

    } else if (string_compare(args[0], "tree") == 0) {
        terminal_write_string("\nDirectory Structure:\n");
        terminal_write_string("====================\n");

        char current_dir[FS_MAX_PATH_LENGTH];
        filesystem_get_current_directory(current_dir, sizeof(current_dir));

        terminal_set_color(12, 0);
        terminal_write_string(current_dir);
        terminal_set_color(7, 0);
        terminal_write_string("\n");

        fs_dir_entry_t entries[64];
        uint32_t count = filesystem_list_directory(NULL, entries, 64);

        for (uint32_t i = 0; i < count; i++) {
            terminal_write_string("|-- ");
            if (entries[i].type == FS_TYPE_DIRECTORY) {
                terminal_set_color(12, 0);
                terminal_write_string(entries[i].name);
                terminal_write_string("/");
                terminal_set_color(7, 0);
            } else {
                terminal_set_color(11, 0);
                terminal_write_string(entries[i].name);
                terminal_set_color(7, 0);
            }
            terminal_write_string("\n");
        }

    } else if (string_compare(args[0], "grep") == 0) {
        if (argc < 3) {
            terminal_write_string("\nUsage: grep <pattern> <file>\n");
        } else {
            if (!filesystem_file_exists(args[2])) {
                terminal_write_string("\nError: File '");
                terminal_write_string(args[2]);
                terminal_write_string("' does not exist.\n");
            } else {
                fs_file_handle_t* handle = filesystem_open_file(args[2], false);
                if (!handle) {
                    terminal_write_string("\nError: Cannot open file.\n");
                } else {
                    terminal_write_string("\nSearching for '");
                    terminal_write_string(args[1]);
                    terminal_write_string("' in ");
                    terminal_write_string(args[2]);
                    terminal_write_string(":\n\n");

                    char buffer[512];
                    uint32_t bytes_read = filesystem_read_file(handle, buffer, sizeof(buffer) - 1);
                    buffer[bytes_read] = '\0';

                    filesystem_close_file(handle);

                    if (string_contains(buffer, args[1])) {
                        terminal_set_color(10, 0);
                        terminal_write_string("Pattern found in file\n");
                        terminal_set_color(7, 0);

                        char* line_start = buffer;
                        uint32_t line_num = 1;

                        for (uint32_t i = 0; i < bytes_read; i++) {
                            if (buffer[i] == '\n' || i == bytes_read - 1) {
                                buffer[i] = '\0';
                                if (string_contains(line_start, args[1])) {
                                    terminal_write_uint(line_num);
                                    terminal_write_string(": ");
                                    terminal_write_string(line_start);
                                    terminal_write_string("\n");
                                }
                                line_start = &buffer[i + 1];
                                line_num++;
                                buffer[i] = '\n';
                            }
                        }
                    } else {
                        terminal_write_string("Pattern not found in file.\n");
                    }
                }
            }
        }

    } else if (string_compare(args[0], "sysinfo") == 0) {
        terminal_write_string("\nApollo Operating System - System Information\n");
        terminal_write_string("============================================\n\n");

        terminal_set_color(14, 0);
        terminal_write_string("Kernel Information:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  Kernel Version:    Apollo v1.1.2\n");
        terminal_write_string("  Architecture:      x86_64\n");
        terminal_write_string("  Build Date:        " __DATE__ " " __TIME__ "\n");
        terminal_write_string("  Compiler:          GCC " __VERSION__ "\n\n");

        terminal_set_color(12, 0);
        terminal_write_string("Hardware Information:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  CPU:               x86_64 Compatible\n");
        terminal_write_string("  Memory Model:      Long Mode (64-bit)\n");
        terminal_write_string("  Boot Protocol:     Multiboot2\n");
        terminal_write_string("  Graphics:          VGA Text Mode 80x25\n\n");

        terminal_set_color(10, 0);
        terminal_write_string("Memory Information:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  Total Heap:       ");
        terminal_write_uint(heap_allocator_get_total_memory() / 1024);
        terminal_write_string(" KB\n");
        terminal_write_string("  Used Memory:       ");
        terminal_write_uint(heap_allocator_get_used_memory() / 1024);
        terminal_write_string(" KB\n");
        terminal_write_string("  Free Memory:       ");
        terminal_write_uint(heap_allocator_get_free_memory() / 1024);
        terminal_write_string(" KB\n\n");

        terminal_set_color(11, 0);
        terminal_write_string("System Statistics:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  Commands Executed: ");
        terminal_write_uint(shell.commands_executed);
        terminal_write_string("\n");
        terminal_write_string("  Uptime:            ");
        terminal_write_uint(time_keeper_get_uptime_seconds());
        terminal_write_string(" seconds\n");

        process_stats_t proc_stats;
        if (process_get_stats(&proc_stats)) {
            terminal_write_string("  Kernel Tasks:      ");
            terminal_write_uint(proc_stats.total_processes);
            terminal_write_string("\n");
            terminal_write_string("  Task Switches:     ");
            terminal_write_uint(proc_stats.context_switches);
            terminal_write_string("\n");
        }

        terminal_set_color(9, 0);
        terminal_write_string("\nNetwork Information:\n");
        terminal_set_color(7, 0);
        terminal_write_string("  Network Status:    ");
        if (network_manager_is_connected()) {
            terminal_set_color(10, 0);
            terminal_write_string("Connected");
        } else {
            terminal_set_color(12, 0);
            terminal_write_string("Disconnected");
        }
        terminal_set_color(7, 0);
        terminal_write_string("\n");
        terminal_write_string("  Interfaces:        ");
        terminal_write_uint(network_manager_get_interface_count());
        terminal_write_string(" detected\n");

    } else if (string_compare(args[0], "meminfo") == 0) {
        terminal_write_string("\nMemory Usage Statistics:\n");
        terminal_write_string("========================\n\n");

        uint32_t total = heap_allocator_get_total_memory();
        uint32_t used = heap_allocator_get_used_memory();
        uint32_t free = heap_allocator_get_free_memory();
        uint32_t usage_percent = (used * 100) / total;

        terminal_write_string("Total Memory:  ");
        terminal_write_uint(total / 1024);
        terminal_write_string(" KB (");
        terminal_write_uint(total);
        terminal_write_string(" bytes)\n");

        terminal_write_string("Used Memory:   ");
        terminal_write_uint(used / 1024);
        terminal_write_string(" KB (");
        terminal_write_uint(used);
        terminal_write_string(" bytes)\n");

        terminal_write_string("Free Memory:   ");
        terminal_write_uint(free / 1024);
        terminal_write_string(" KB (");
        terminal_write_uint(free);
        terminal_write_string(" bytes)\n");

        terminal_write_string("Memory Usage:  ");
        terminal_write_uint(usage_percent);
        terminal_write_string("%\n\n");

        terminal_write_string("Usage Bar: [");
        for (int i = 0; i < 50; i++) {
            if (i < (int)(usage_percent / 2)) {
                terminal_set_color(12, 0); // Red for used
                terminal_write_char('#');
            } else {
                terminal_set_color(10, 0); // Green for free
                terminal_write_char('-');
            }
        }
        terminal_set_color(7, 0);
        terminal_write_string("]\n");

    } else if (string_compare(args[0], "df") == 0) {
        terminal_write_string("\nFilesystem Usage:\n");
        terminal_write_string("=================\n\n");

        fs_stats_t stats;
        if (filesystem_get_stats(&stats)) {
            terminal_write_string("Filesystem:    Apollo FS\n");
            terminal_write_string("Total Space:   ");
            terminal_write_uint(stats.total_space / 1024);
            terminal_write_string(" KB\n");
            terminal_write_string("Used Space:    ");
            terminal_write_uint((stats.total_space - stats.free_space) / 1024);
            terminal_write_string(" KB\n");
            terminal_write_string("Free Space:    ");
            terminal_write_uint(stats.free_space / 1024);
            terminal_write_string(" KB\n");
            terminal_write_string("Total Files:   ");
            terminal_write_uint(stats.total_files);
            terminal_write_string("\n");
            terminal_write_string("Directories:   ");
            terminal_write_uint(stats.total_directories);
            terminal_write_string("\n");
            terminal_write_string("Free Pages:    ");
            terminal_write_uint(stats.free_pages);
            terminal_write_string(" (shared with programs)\n");
            terminal_write_string("Used Pages:    ");
            terminal_write_uint(stats.used_pages);
            terminal_write_string("\n");

            uint32_t usage_percent = ((stats.total_space - stats.free_space) * 100) / stats.total_space;
            terminal_write_string("Usage:         ");
            terminal_write_uint(usage_percent);
            terminal_write_string("%\n");
        }

    } else if (string_compare(args[0], "ps") == 0) {
        command_ps();

    } else if (string_compare(args[0], "whoami") == 0) {
        terminal_write_string("\nUser Information:\n");
        terminal_write_string("=================\n");
        terminal_write_string("Username:      ");
        terminal_write_string(shell.current_user);
        terminal_write_string("\n");
        terminal_write_string("Shell:         Apollo Shell v1.1.2\n");
        terminal_write_string("Session ID:    ");
        terminal_write_uint(shell.session_id);
        terminal_write_string("\n");
        terminal_write_string("Commands Run:  ");
        terminal_write_uint(shell.commands_executed);
        terminal_write_string("\n");

    } else if (string_compare(args[0], "date") == 0) {
        int year, month, day, hour, minute, second;
        time_keeper_get_datetime(&year, &month, &day, &hour, &minute, &second);

        const char* months[] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };

        terminal_write_string("\nCurrent Date and Time:\n");
        terminal_write_string("======================\n");
        terminal_write_string("Date: ");
        terminal_write_string(months[month - 1]);
        terminal_write_string(" ");
        terminal_write_uint(day);
        terminal_write_string(", ");
        terminal_write_uint(year);
        terminal_write_string("\n");

        terminal_write_string("Time: ");
        if (hour < 10) terminal_write_string("0");
        terminal_write_uint(hour);
        terminal_write_string(":");
        if (minute < 10) terminal_write_string("0");
        terminal_write_uint(minute);
        terminal_write_string(":");
        if (second < 10) terminal_write_string("0");
        terminal_write_uint(second);
        terminal_write_string("\n");

    } else if (string_compare(args[0], "uptime") == 0) {
        uint64_t uptime = time_keeper_get_uptime_seconds();
        uint32_t hours = uptime / 3600;
        uint32_t minutes = (uptime % 3600) / 60;
        uint32_t seconds = uptime % 60;

        terminal_write_string("\nSystem Uptime:\n");
        terminal_write_string("==============\n");
        terminal_write_string("Uptime: ");
        terminal_write_uint(hours);
        terminal_write_string(" hours, ");
        terminal_write_uint(minutes);
        terminal_write_string(" minutes, ");
        terminal_write_uint(seconds);
        terminal_write_string(" seconds\n");
        terminal_write_string("Total: ");
        terminal_write_uint((uint32_t)uptime);
        terminal_write_string(" seconds\n");

    } else if (string_compare(args[0], "calc") == 0) {
        if (argc < 2) {
            terminal_write_string("\nApollo Calculator\n");
            terminal_write_string("=========================================\n\n");
            terminal_write_string("Usage: calc <expression>\n\n");
            terminal_write_string("Supported operators: + - * / %\n");
            terminal_write_string("Examples:\n");
            terminal_write_string("  calc 15 + 25         = 40\n");
            terminal_write_string("  calc 64287 + 8732    = 72019\n");
            terminal_write_string("  calc 100 * 5 / 2     = 250\n");
            terminal_write_string("  calc 300 * 0 / 0     = Error: Division by zero\n\n");
            terminal_write_string("Note: Operations are evaluated left to right\n");
        } else {
            char expr[512] = "";
            for (uint32_t i = 1; i < argc; i++) {
                string_append(expr, args[i]);
                if (i < argc - 1) {
                    string_append(expr, " ");
                }
            }

            char check_args[MAX_ARGUMENTS][MAX_COMMAND_LENGTH];
            uint32_t check_count = parse_arguments(expr, check_args);
            bool has_div_by_zero = false;

            for (uint32_t i = 1; i < check_count; i += 2) {
                if (i + 1 < check_count) {
                    char op = check_args[i][0];
                    int operand = string_to_integer(check_args[i + 1]);
                    if ((op == '/' || op == '%') && operand == 0) {
                        has_div_by_zero = true;
                        break;
                    }
                }
            }

            terminal_write_string("\n");

            if (has_div_by_zero) {
                terminal_set_color(12, 0); // Red
                terminal_write_string("Error: Division by zero detected\n");
                terminal_set_color(7, 0);
                terminal_write_string("Expression: ");
                terminal_write_string(expr);
                terminal_write_string("\n");
            } else {
                int result = calculate_expression(expr);
                terminal_set_color(10, 0); // Green
                terminal_write_string("Result: ");
                terminal_set_color(7, 0);
                terminal_write_string(expr);
                terminal_write_string(" = ");
                terminal_set_color(14, 0); // Yellow
                terminal_write_int(result);
                terminal_set_color(7, 0);
                terminal_write_string("\n");
            }
        }

    } else if (string_compare(args[0], "echo") == 0) {
        terminal_write_string("\n");
        for (uint32_t i = 1; i < argc; i++) {
            terminal_write_string(args[i]);
            if (i < argc - 1) terminal_write_string(" ");
        }
        terminal_write_string("\n");

    } else if (string_compare(args[0], "history") == 0) {
        terminal_write_string("\nCommand History:\n");
        terminal_write_string("================\n");

        if (history.count == 0) {
            terminal_write_string("No commands in history.\n");
        } else {
            for (uint32_t i = 0; i < history.count; i++) {
                uint32_t idx = (history.write_index - history.count + i + COMMAND_HISTORY_SIZE) % COMMAND_HISTORY_SIZE;
                terminal_write_uint(i + 1);
                terminal_write_string(": ");
                terminal_write_string(history.entries[idx]);
                terminal_write_string("\n");
            }
        }

    } else if (string_compare(args[0], "palette") == 0) {
        terminal_write_string("\nApollo Color Palette Demonstration:\n");
        terminal_write_string("====================================\n\n");

        for (int bg = 0; bg < 8; bg++) {
            for (int fg = 0; fg < 16; fg++) {
                terminal_set_color(fg, bg);
                terminal_write_char('#');
            }
            terminal_set_color(7, 0);
            terminal_write_string("  Background ");
            terminal_write_uint(bg);
            terminal_write_string("\n");
        }

        terminal_write_string("\nForeground Colors:\n");
        for (int i = 0; i < 16; i++) {
            terminal_set_color(i, 0);
            terminal_write_uint(i);
            terminal_write_string(":");
            for (int j = 0; j < 5; j++) {
                terminal_write_char('#');
            }
            terminal_set_color(7, 0);
            terminal_write_string(" ");

            if ((i + 1) % 8 == 0) terminal_write_string("\n");
        }
        terminal_write_string("\n");

    } else if (string_compare(args[0], "edit") == 0) {
        const char* filename = (argc > 1) ? args[1] : NULL;
        terminal_write_string("\nLaunching Apollo Text Editor...\n");
        if (filename) {
            terminal_write_string("File: ");
            terminal_write_string(filename);
            terminal_write_string("\n");
        }
        text_editor_run(filename);
        terminal_clear();
        terminal_write_string("Returned to shell.\n");

    } else if (string_compare(args[0], "ifconfig") == 0) {
        terminal_write_string("\nNetwork Interface Configuration:\n");
        terminal_write_string("=================================\n");

        if (argc == 1) {
            network_manager_dump_interface_info();
        } else if (argc >= 4 && string_compare(args[2], "static") == 0) {
            ip_address_t ip, netmask, gateway = {0};
            if (string_to_ip_address(args[3], &ip) &&
                (argc < 5 || string_to_ip_address(args[4], &netmask)) &&
                (argc < 6 || string_to_ip_address(args[5], &gateway))) {

                if (network_manager_configure_static_ip(args[1], &ip, &netmask, &gateway)) {
                    terminal_write_string("Static IP configured successfully\n");
                } else {
                    terminal_write_string("Failed to configure static IP\n");
                }
            } else {
                terminal_write_string("Invalid IP address format\n");
                terminal_write_string("Usage: ifconfig <interface> static <ip> [netmask] [gateway]\n");
            }
        } else if (argc == 3 && string_compare(args[2], "dhcp") == 0) {
            if (network_manager_enable_dhcp(args[1])) {
                terminal_write_string("DHCP enabled on interface ");
                terminal_write_string(args[1]);
                terminal_write_string("\n");
            } else {
                terminal_write_string("Failed to enable DHCP\n");
            }
        } else if (argc == 3 && string_compare(args[2], "up") == 0) {
            if (network_manager_bring_interface_up(args[1])) {
                terminal_write_string("Interface ");
                terminal_write_string(args[1]);
                terminal_write_string(" brought up\n");
            } else {
                terminal_write_string("Failed to bring interface up\n");
            }
        } else if (argc == 3 && string_compare(args[2], "down") == 0) {
            if (network_manager_bring_interface_down(args[1])) {
                terminal_write_string("Interface ");
                terminal_write_string(args[1]);
                terminal_write_string(" brought down\n");
            } else {
                terminal_write_string("Failed to bring interface down\n");
            }
        } else {
            terminal_write_string("Usage:\n");
            terminal_write_string("  ifconfig                              - Show all interfaces\n");
            terminal_write_string("  ifconfig <iface> static <ip> <mask>   - Configure static IP\n");
            terminal_write_string("  ifconfig <iface> dhcp                 - Enable DHCP\n");
            terminal_write_string("  ifconfig <iface> up|down              - Bring interface up/down\n");
        }

    } else if (string_compare(args[0], "listen") == 0) {
        net_cmd_listen((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "ping") == 0) {
        net_cmd_ping((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "nslookup") == 0) {
        net_cmd_nslookup((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "netstat") == 0) {
        net_cmd_netstat((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "dhcp") == 0) {
        net_cmd_dhcp((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "wget") == 0) {
        net_cmd_wget((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "netstatus") == 0) {
        terminal_write_string("\nDetailed Network Status:\n");
        terminal_write_string("========================\n");

        terminal_write_string("Connection Status: ");
        if (network_manager_is_connected()) {
            terminal_set_color(10, 0);  // Green
            terminal_write_string("CONNECTED\n");
            terminal_set_color(7, 0);

            network_interface_t* default_iface = network_manager_get_default_interface();
            if (default_iface) {
                char ip_str[16], gateway_str[16];
                ip_address_to_string(&default_iface->ip_addr, ip_str);
                ip_address_to_string(&default_iface->gateway, gateway_str);

                terminal_write_string("Default Interface: ");
                terminal_write_string(default_iface->name);
                terminal_write_string(" (");
                terminal_write_string(ip_str);
                terminal_write_string(")\n");
                terminal_write_string("Default Gateway: ");
                terminal_write_string(gateway_str);
                terminal_write_string("\n");
            }
        } else {
            terminal_set_color(12, 0);  // Red
            terminal_write_string("DISCONNECTED\n");
            terminal_set_color(7, 0);
        }

        terminal_write_string("\n");

        network_manager_dump_interface_info();

        dns_config_t* dns_config = dns_get_config();
        terminal_write_string("DNS Configuration:\n");
        terminal_write_string("  DNS Servers:  ");
        if (dns_config->num_dns_servers == 0) {
            terminal_write_string("None configured\n");
        } else {
            terminal_write_string("\n");
            for (uint8_t i = 0; i < dns_config->num_dns_servers; i++) {
                char dns_str[16];
                ip_address_to_string(&dns_config->dns_servers[i], dns_str);
                terminal_write_string("    ");
                terminal_write_uint(i + 1);
                terminal_write_string(". ");
                terminal_write_string(dns_str);
                terminal_write_string("\n");
            }
        }
        terminal_write_string("  Cache Enabled: ");
        terminal_write_string(dns_config->cache_enabled ? "Yes" : "No");
        terminal_write_string("\n");
        terminal_write_string("  Cache Entries: ");
        terminal_write_uint(dns_cache_get_entry_count());
        terminal_write_string("\n");

        network_statistics_t* net_stats = network_get_statistics();
        terminal_write_string("\nProtocol Statistics:\n");
        terminal_write_string("  IP Packets:   ");
        terminal_write_uint((uint32_t)net_stats->ip_packets_sent);
        terminal_write_string(" sent, ");
        terminal_write_uint((uint32_t)net_stats->ip_packets_received);
        terminal_write_string(" received\n");
        terminal_write_string("  ARP Messages: ");
        terminal_write_uint((uint32_t)net_stats->arp_requests_sent);
        terminal_write_string(" requests, ");
        terminal_write_uint((uint32_t)net_stats->arp_replies_received);
        terminal_write_string(" replies\n");
        terminal_write_string("  ICMP:         ");
        terminal_write_uint((uint32_t)net_stats->icmp_packets_sent);
        terminal_write_string(" sent, ");
        terminal_write_uint((uint32_t)net_stats->icmp_packets_received);
        terminal_write_string(" received\n");
        terminal_write_string("  UDP:          ");
        terminal_write_uint((uint32_t)net_stats->udp_packets_sent);
        terminal_write_string(" sent, ");
        terminal_write_uint((uint32_t)net_stats->udp_packets_received);
        terminal_write_string(" received\n");

        dhcp_statistics_t* dhcp_stats = dhcp_get_statistics();
        terminal_write_string("\nDHCP Statistics:\n");
        terminal_write_string("  Discovers:    ");
        terminal_write_uint(dhcp_stats->discovers_sent);
        terminal_write_string("\n");
        terminal_write_string("  Offers:       ");
        terminal_write_uint(dhcp_stats->offers_received);
        terminal_write_string("\n");
        terminal_write_string("  Requests:     ");
        terminal_write_uint(dhcp_stats->requests_sent);
        terminal_write_string("\n");
        terminal_write_string("  ACKs:         ");
        terminal_write_uint(dhcp_stats->acks_received);
        terminal_write_string("\n");
        terminal_write_string("  Active Leases:");
        terminal_write_uint(dhcp_stats->leases_acquired);
        terminal_write_string("\n");

        dns_statistics_t* dns_stats = dns_get_statistics();
        terminal_write_string("\nDNS Statistics:\n");
        terminal_write_string("  Queries:      ");
        terminal_write_uint(dns_stats->queries_sent);
        terminal_write_string(" sent, ");
        terminal_write_uint(dns_stats->successful_resolutions);
        terminal_write_string(" successful\n");
        terminal_write_string("  Cache:        ");
        terminal_write_uint(dns_stats->cache_hits);
        terminal_write_string(" hits, ");
        terminal_write_uint(dns_stats->cache_misses);
        terminal_write_string(" misses\n");
        terminal_write_string("  Timeouts:     ");
        terminal_write_uint(dns_stats->timeouts);
        terminal_write_string("\n");

    } else if (string_compare(args[0], "nettest") == 0) {
        terminal_write_string("\nNetwork Stack Test\n");
        terminal_write_string("=================================\n");

        bool all_good = true;

        terminal_write_string("\n1. RTL8139 Driver Status:\n");
        uint32_t if_count = network_manager_get_interface_count();
        terminal_write_string("   Interfaces detected: ");
        terminal_write_uint(if_count);
        terminal_write_string("\n");

        if (if_count == 0) {
            terminal_set_color(12, 0);  // Red
            terminal_write_string("   Error: no network interfaces found\n");
            terminal_set_color(7, 0);
            all_good = false;
        } else {
            terminal_set_color(10, 0);  // Green
            terminal_write_string("   Network interfaces detected\n");
            terminal_set_color(7, 0);
        }

        terminal_write_string("\n2. Interface Configuration:\n");
        network_interface_t* iface = network_interface_get_default();
        if (iface) {
            terminal_write_string("   Default Interface: ");
            terminal_write_string(iface->name);
            terminal_write_string("\n");

            char mac_str[18];
            mac_address_to_string(&iface->mac_addr, mac_str);
            terminal_write_string("   MAC Address: ");
            terminal_write_string(mac_str);
            terminal_write_string("\n");

            terminal_write_string("   State: ");
            bool state_ok = false;
            switch (iface->state) {
                case NET_INTERFACE_DOWN:
                    terminal_set_color(12, 0);
                    terminal_write_string("DOWN");
                    break;
                case NET_INTERFACE_UP:
                    terminal_set_color(10, 0);
                    terminal_write_string("UP");
                    state_ok = true;
                    break;
                case NET_INTERFACE_LINK_DOWN:
                    terminal_set_color(14, 0);
                    terminal_write_string("LINK_DOWN");
                    break;
                case NET_INTERFACE_LINK_UP:
                    terminal_set_color(11, 0);
                    terminal_write_string("LINK_UP ");
                    state_ok = true;
                    break;
            }
            terminal_set_color(7, 0);
            terminal_write_string("\n");

            if (!state_ok) all_good = false;

            if (iface->ip_addr.addr != 0) {
                char ip_str[16], mask_str[16], gw_str[16];
                ip_address_to_string(&iface->ip_addr, ip_str);
                ip_address_to_string(&iface->netmask, mask_str);
                ip_address_to_string(&iface->gateway, gw_str);

                terminal_set_color(10, 0);
                terminal_write_string("    IP Configuration:\n");
                terminal_set_color(7, 0);
                terminal_write_string("     IP: ");
                terminal_write_string(ip_str);
                terminal_write_string("\n");
                terminal_write_string("     Netmask: ");
                terminal_write_string(mask_str);
                terminal_write_string("\n");
                terminal_write_string("     Gateway: ");
                terminal_write_string(gw_str);
                terminal_write_string("\n");
            } else {
                terminal_set_color(14, 0);
                terminal_write_string("     No IP configuration\n");
                terminal_set_color(7, 0);
                all_good = false;
            }
        } else {
            terminal_set_color(12, 0);
            terminal_write_string("    No default interface available\n");
            terminal_set_color(7, 0);
            all_good = false;
        }

        terminal_write_string("\n3. Packet Reception Test:\n");
        if (iface) {
            terminal_write_string("   Testing packet reception...\n");

            for (int i = 0; i < 10; i++) {
                network_interface_process_incoming_packets();
            }

            terminal_write_string("   RX Packets: ");
            terminal_write_uint((uint32_t)iface->rx_packets);
            terminal_write_string(", TX Packets: ");
            terminal_write_uint((uint32_t)iface->tx_packets);
            terminal_write_string("\n");
            terminal_write_string("   RX Errors: ");
            terminal_write_uint((uint32_t)iface->rx_errors);
            terminal_write_string(", TX Errors: ");
            terminal_write_uint((uint32_t)iface->tx_errors);
            terminal_write_string("\n");

            if (iface->rx_errors > iface->rx_packets / 2) {
                terminal_set_color(12, 0);
                terminal_write_string("    High error rate detected\n");
                terminal_set_color(7, 0);
                all_good = false;
            }
        }

        terminal_write_string("\n4. ARP Table Status:\n");
        network_statistics_t* stats = network_get_statistics();
        terminal_write_string("   ARP Requests Sent: ");
        terminal_write_uint((uint32_t)stats->arp_requests_sent);
        terminal_write_string("\n");
        terminal_write_string("   ARP Replies Received: ");
        terminal_write_uint((uint32_t)stats->arp_replies_received);
        terminal_write_string("\n");

        if (stats->arp_requests_sent > 0 && stats->arp_replies_received == 0) {
            terminal_set_color(12, 0);
            terminal_write_string("    ARP not working - no replies received\n");
            terminal_set_color(7, 0);
            all_good = false;
        }

        terminal_write_string("\n5. DHCP Client Status:\n");
        dhcp_statistics_t* dhcp_stats = dhcp_get_statistics();
        terminal_write_string("   DHCP Discovers: ");
        terminal_write_uint(dhcp_stats->discovers_sent);
        terminal_write_string("\n");
        terminal_write_string("   DHCP Offers: ");
        terminal_write_uint(dhcp_stats->offers_received);
        terminal_write_string("\n");
        terminal_write_string("   DHCP ACKs: ");
        terminal_write_uint(dhcp_stats->acks_received);
        terminal_write_string("\n");
        terminal_write_string("   Active Leases: ");
        terminal_write_uint(dhcp_stats->leases_acquired);
        terminal_write_string("\n");

        terminal_write_string("\n6. Result:\n");
        if (all_good && iface && iface->ip_addr.addr != 0) {
            terminal_set_color(10, 0);
            terminal_write_string("  No errors\n");
            terminal_set_color(7, 0);
        } else {
            print_network_result(iface);
        }

    } else if (string_compare(args[0], "rawsend") == 0) {
        if (argc < 2) {
            terminal_write_string("\nUsage: rawsend <test_message>\n");
            terminal_write_string("Sends a raw UDP test packet to 8.8.8.8:53\n");
        } else {
            network_interface_t* iface = network_interface_get_default();
            if (!iface) {
                terminal_write_string("\nNo default interface available\n");
                return;
            }

            if (iface->ip_addr.addr == 0) {
                terminal_write_string("\nInterface has no IP address. Configure network first:\n");
                terminal_write_string("  ifconfig eth0 static 10.0.2.15 255.255.255.0 10.0.2.2\n");
                terminal_write_string("  OR\n");
                terminal_write_string("  dhcp eth0\n");
                return;
            }

            terminal_write_string("\nSending raw test packet to 8.8.8.8:53...\n");

            udp_socket_t* test_socket = udp_create_socket();
            if (test_socket && udp_bind_socket(test_socket, 12345)) {
                ip_address_t test_ip = {.addr = 0x08080808};  // 8.8.8.8 in network byte order

                char test_message[256] = "Apollo OS test: ";
                string_append(test_message, args[1]);

                bool success = udp_send_to(test_socket, &test_ip, 53, test_message, string_length(test_message));

                if (success) {
                    terminal_set_color(10, 0);  // Green
                    terminal_write_string("Raw packet sent successfully\n");
                    terminal_write_string("Message: ");
                    terminal_write_string(test_message);
                    terminal_write_string("\n");
                    terminal_write_string("Destination: 8.8.8.8:53\n");
                    terminal_set_color(7, 0);
                } else {
                    terminal_set_color(12, 0);  // Red
                    terminal_write_string("Raw packet send failed\n");
                    terminal_set_color(7, 0);
                }

                udp_close_socket(test_socket);
            } else {
                terminal_write_string("Failed to create test socket\n");
            }
        }

    } else if (string_compare(args[0], "netinfo") == 0) {
        terminal_write_string("\nComplete Network Information\n");
        terminal_write_string("============================\n");

        network_manager_dump_interface_info();

        dns_config_t* dns_config = dns_get_config();
        terminal_write_string("\nDNS Configuration:\n");
        terminal_write_string("  Servers: ");
        if (dns_config->num_dns_servers == 0) {
            terminal_write_string("None configured");
        } else {
            for (uint8_t i = 0; i < dns_config->num_dns_servers; i++) {
                char dns_str[16];
                ip_address_to_string(&dns_config->dns_servers[i], dns_str);
                terminal_write_string(dns_str);
                if (i < dns_config->num_dns_servers - 1) terminal_write_string(", ");
            }
        }
        terminal_write_string("\n");
        terminal_write_string("  Cache: ");
        terminal_write_uint(dns_cache_get_entry_count());
        terminal_write_string(" entries\n");

        network_statistics_t* net_stats = network_get_statistics();
        dhcp_statistics_t* dhcp_stats = dhcp_get_statistics();
        dns_statistics_t* dns_stats = dns_get_statistics();

        terminal_write_string("\nProtocol Statistics:\n");
        terminal_write_string("  IP:   ");
        terminal_write_uint((uint32_t)net_stats->ip_packets_sent);
        terminal_write_string(" sent, ");
        terminal_write_uint((uint32_t)net_stats->ip_packets_received);
        terminal_write_string(" received\n");

        terminal_write_string("  UDP:  ");
        terminal_write_uint((uint32_t)net_stats->udp_packets_sent);
        terminal_write_string(" sent, ");
        terminal_write_uint((uint32_t)net_stats->udp_packets_received);
        terminal_write_string(" received\n");

        terminal_write_string("  DHCP: ");
        terminal_write_uint(dhcp_stats->leases_acquired);
        terminal_write_string(" leases, ");
        terminal_write_uint(dhcp_stats->discovers_sent);
        terminal_write_string(" discovers\n");

        terminal_write_string("  DNS:  ");
        terminal_write_uint(dns_stats->successful_resolutions);
        terminal_write_string(" successful, ");
        terminal_write_uint(dns_stats->timeouts);
        terminal_write_string(" timeouts\n");

    } else if (string_compare(args[0], "arp") == 0) {
        net_cmd_arp((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "route") == 0) {
        net_cmd_route((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "tcpdump") == 0) {
        net_cmd_tcpdump((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "traceroute") == 0) {
        net_cmd_traceroute((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "telnet") == 0) {
        net_cmd_telnet((int)argc, arg_ptrs);

    } else if (string_compare(args[0], "arpping") == 0) {
        if (argc < 2) {
            terminal_write_string("\nUsage: arpping <ip_address>\n");
            terminal_write_string("Sends ARP request to populate ARP table\n");
            terminal_write_string("Example: arpping 10.0.2.2\n");
            terminal_write_string("Example: arpping 10.0.2.1\n");
            terminal_write_string("Remote addresses resolve the gateway instead\n");
        } else {
            network_interface_t* iface = network_interface_get_default();
            if (!iface) {
                terminal_write_string("\nNo default interface available\n");
                return;
            }

            terminal_write_string("\nInterface Status:\n");
            terminal_write_string("  Name: ");
            terminal_write_string(iface->name);
            terminal_write_string("\n");
            terminal_write_string("  State: ");
            switch (iface->state) {
                case NET_INTERFACE_DOWN: terminal_write_string("DOWN"); break;
                case NET_INTERFACE_UP: terminal_write_string("UP"); break;
                case NET_INTERFACE_LINK_DOWN: terminal_write_string("LINK_DOWN"); break;
                case NET_INTERFACE_LINK_UP: terminal_write_string("LINK_UP"); break;
            }
            terminal_write_string("\n");

            if (iface->ip_addr.addr == 0) {
                terminal_set_color(12, 0);  // Red
                terminal_write_string("  ERROR: Interface has no IP address\n");
                terminal_write_string("  Configure network first:\n");
                terminal_write_string("    ifconfig eth0 static 10.0.2.15 255.255.255.0 10.0.2.2\n");
                terminal_write_string("    OR\n");
                terminal_write_string("    dhcp eth0\n");
                terminal_set_color(7, 0);
                return;
            }

            char ip_str[16], mask_str[16], gw_str[16];
            ip_address_to_string(&iface->ip_addr, ip_str);
            ip_address_to_string(&iface->netmask, mask_str);
            ip_address_to_string(&iface->gateway, gw_str);

            terminal_write_string("  IP: ");
            terminal_write_string(ip_str);
            terminal_write_string("\n");
            terminal_write_string("  Netmask: ");
            terminal_write_string(mask_str);
            terminal_write_string("\n");
            terminal_write_string("  Gateway: ");
            terminal_write_string(gw_str);
            terminal_write_string("\n");

            ip_address_t target_ip;
            if (!string_to_ip_address(args[1], &target_ip)) {
                terminal_write_string("\nInvalid IP address format\n");
                return;
            }

            terminal_write_string("\nTesting ARP resolution for ");
            terminal_write_string(args[1]);
            terminal_write_string("...\n");

            ip_address_t arp_target;
            bool is_local_target;

            if (ip_address_is_in_subnet(&target_ip, &iface->ip_addr, &iface->netmask)) {
                terminal_write_string("Target is on local network - sending direct ARP request\n");
                arp_target = target_ip;
                is_local_target = true;
            } else if (iface->gateway.addr != 0) {
                terminal_write_string("Target is remote - sending ARP request for gateway ");
                terminal_write_string(gw_str);
                terminal_write_string("\n");
                terminal_write_string("(This is how IP routing works - to reach remote hosts, we need the gateway's MAC)\n");
                arp_target = iface->gateway;
                is_local_target = false;
            } else {
                terminal_set_color(12, 0);
                terminal_write_string("ERROR: No gateway configured for remote target\n");
                terminal_write_string("Configure a gateway with: ifconfig eth0 static <ip> <mask> <gateway>\n");
                terminal_set_color(7, 0);
                return;
            }

            mac_address_t resolved_mac;
            bool success = arp_resolve_ip(iface, &arp_target, &resolved_mac);

            if (success) {
                terminal_set_color(10, 0);  // Green
                terminal_write_string("\nARP Resolution Successful\n");
                terminal_set_color(7, 0);

                char mac_str[18];
                mac_address_to_string(&resolved_mac, mac_str);

                if (is_local_target) {
                    terminal_write_string("Direct ARP: IP ");
                    terminal_write_string(args[1]);
                    terminal_write_string(" -> MAC ");
                    terminal_write_string(mac_str);
                    terminal_write_string("\n");
                } else {
                    terminal_write_string("Gateway ARP: IP ");
                    terminal_write_string(gw_str);
                    terminal_write_string(" -> MAC ");
                    terminal_write_string(mac_str);
                    terminal_write_string("\n");
                    terminal_write_string("(Gateway MAC will be used to route packets to ");
                    terminal_write_string(args[1]);
                    terminal_write_string(")\n");
                }

                terminal_write_string("\nUpdated ARP table:\n");
                arp_dump_table();
            } else {
                terminal_set_color(12, 0);  // Red
                terminal_write_string("\nARP Resolution Failed\n");
                terminal_set_color(7, 0);

                if (is_local_target) {
                    terminal_write_string("Failed to resolve ");
                    terminal_write_string(args[1]);
                    terminal_write_string(" (local target)\n");
                } else {
                    terminal_write_string("Failed to resolve gateway ");
                    terminal_write_string(gw_str);
                    terminal_write_string("\n");
                }

                print_arp_failure(iface, &arp_target);
                print_qemu_network_hint();
            }

            terminal_write_string("\nNetwork Statistics:\n");
            network_statistics_t* stats = network_get_statistics();
            terminal_write_string("  ARP requests sent: ");
            terminal_write_uint((uint32_t)stats->arp_requests_sent);
            terminal_write_string("\n");
            terminal_write_string("  ARP replies received: ");
            terminal_write_uint((uint32_t)stats->arp_replies_received);
            terminal_write_string("\n");
            terminal_write_string("  Interface TX packets: ");
            terminal_write_uint((uint32_t)iface->tx_packets);
            terminal_write_string(", RX packets: ");
            terminal_write_uint((uint32_t)iface->rx_packets);
            terminal_write_string("\n");
            terminal_write_string("  Interface TX errors: ");
            terminal_write_uint((uint32_t)iface->tx_errors);
            terminal_write_string(", RX errors: ");
            terminal_write_uint((uint32_t)iface->rx_errors);
            terminal_write_string("\n");
        }
    } else if (string_compare(args[0], "netdiag") == 0) {
        terminal_write_string("\nAdvanced Network Diagnostics\n");
        terminal_write_string("============================\n");

        terminal_write_string("Processing pending packets...\n");
        for (int i = 0; i < 20; i++) {
            network_interface_process_incoming_packets();
            network_manager_periodic_tasks();
        }
        terminal_write_string("\n");

        terminal_write_string("1. Hardware Layer (RTL8139):\n");
        network_interface_t* iface = network_interface_get_default();
        if (iface && iface->driver_data) {
            rtl8139_device_t* device = (rtl8139_device_t*)iface->driver_data;
            rtl8139_dump_status(device);
        } else {
            terminal_write_string("   No RTL8139 device data available\n");
        }

        terminal_write_string("\n2. Data Link Layer (Ethernet):\n");
        if (iface) {
            char mac_str[18];
            mac_address_to_string(&iface->mac_addr, mac_str);
            terminal_write_string("   MAC Address: ");
            terminal_write_string(mac_str);
            terminal_write_string("\n");
            terminal_write_string("   Frame Statistics:\n");
            terminal_write_string("     TX Frames: ");
            terminal_write_uint((uint32_t)iface->tx_packets);
            terminal_write_string(" (");
            terminal_write_uint((uint32_t)(iface->tx_bytes / 1024));
            terminal_write_string(" KB)\n");
            terminal_write_string("     RX Frames: ");
            terminal_write_uint((uint32_t)iface->rx_packets);
            terminal_write_string(" (");
            terminal_write_uint((uint32_t)(iface->rx_bytes / 1024));
            terminal_write_string(" KB)\n");
            terminal_write_string("     TX Errors: ");
            terminal_write_uint((uint32_t)iface->tx_errors);
            terminal_write_string(", RX Errors: ");
            terminal_write_uint((uint32_t)iface->rx_errors);
            terminal_write_string("\n");
        }

        terminal_write_string("\n3. Network Layer (IP/ARP):\n");
        network_statistics_t* net_stats = network_get_statistics();
        terminal_write_string("   IP Packets: ");
        terminal_write_uint((uint32_t)net_stats->ip_packets_sent);
        terminal_write_string(" sent, ");
        terminal_write_uint((uint32_t)net_stats->ip_packets_received);
        terminal_write_string(" received, ");
        terminal_write_uint((uint32_t)net_stats->ip_packets_dropped);
        terminal_write_string(" dropped\n");

        terminal_write_string("   ARP Messages: ");
        terminal_write_uint((uint32_t)net_stats->arp_requests_sent);
        terminal_write_string(" req sent, ");
        terminal_write_uint((uint32_t)net_stats->arp_replies_sent);
        terminal_write_string(" replies sent, ");
        terminal_write_uint((uint32_t)net_stats->arp_replies_received);
        terminal_write_string(" replies received\n");

        terminal_write_string("\n   ARP Table:\n");
        arp_dump_table();

        terminal_write_string("\n4. Transport Layer (UDP):\n");
        terminal_write_string("   UDP Packets: ");
        terminal_write_uint((uint32_t)net_stats->udp_packets_sent);
        terminal_write_string(" sent, ");
        terminal_write_uint((uint32_t)net_stats->udp_packets_received);
        terminal_write_string(" received\n");

        terminal_write_string("\n5. Application Layer:\n");

        dhcp_statistics_t* dhcp_stats = dhcp_get_statistics();
        terminal_write_string("   DHCP: ");
        terminal_write_uint(dhcp_stats->discovers_sent);
        terminal_write_string(" discovers, ");
        terminal_write_uint(dhcp_stats->offers_received);
        terminal_write_string(" offers, ");
        terminal_write_uint(dhcp_stats->acks_received);
        terminal_write_string(" acks, ");
        terminal_write_uint(dhcp_stats->leases_acquired);
        terminal_write_string(" leases\n");

        dns_statistics_t* dns_stats = dns_get_statistics();
        terminal_write_string("   DNS: ");
        terminal_write_uint(dns_stats->queries_sent);
        terminal_write_string(" queries, ");
        terminal_write_uint(dns_stats->successful_resolutions);
        terminal_write_string(" successful, ");
        terminal_write_uint(dns_stats->cache_hits);
        terminal_write_string(" cache hits\n");

        terminal_write_string("\n6. Result:\n");
        print_network_result(iface);

    } else if (string_compare(args[0], "netdebug") == 0) {
        terminal_write_string("\nNetwork Debug\n");
        terminal_write_string("============================\n");

        network_interface_t* iface = network_interface_get_default();
        if (!iface) {
            terminal_set_color(12, 0);
            terminal_write_string("CRITICAL: No default interface found\n");
            terminal_set_color(7, 0);
            return;
        }

        terminal_write_string("\n1. Interface Information:\n");
        terminal_write_string("   Name: ");
        terminal_write_string(iface->name);
        terminal_write_string("\n");

        char mac_str[18];
        mac_address_to_string(&iface->mac_addr, mac_str);
        terminal_write_string("   MAC: ");
        terminal_write_string(mac_str);
        terminal_write_string("\n");

        char ip_str[16], mask_str[16], gw_str[16];
        ip_address_to_string(&iface->ip_addr, ip_str);
        ip_address_to_string(&iface->netmask, mask_str);
        ip_address_to_string(&iface->gateway, gw_str);

        terminal_write_string("   IP: ");
        terminal_write_string(ip_str);
        terminal_write_string("\n");
        terminal_write_string("   Netmask: ");
        terminal_write_string(mask_str);
        terminal_write_string("\n");
        terminal_write_string("   Gateway: ");
        terminal_write_string(gw_str);
        terminal_write_string("\n");

        terminal_write_string("   State: ");
        switch (iface->state) {
            case NET_INTERFACE_DOWN: terminal_write_string("DOWN"); break;
            case NET_INTERFACE_UP: terminal_write_string("UP"); break;
            case NET_INTERFACE_LINK_DOWN: terminal_write_string("LINK_DOWN"); break;
            case NET_INTERFACE_LINK_UP: terminal_write_string("LINK_UP"); break;
        }
        terminal_write_string("\n");

        terminal_write_string("\n2. Testing Raw Packet Transmission:\n");

        typedef struct {
            uint16_t hardware_type;
            uint16_t protocol_type;
            uint8_t hardware_length;
            uint8_t protocol_length;
            uint16_t operation;
            mac_address_t sender_mac;
            ip_address_t sender_ip;
            mac_address_t target_mac;
            ip_address_t target_ip;
        } __attribute__((packed)) test_arp_header_t;

        test_arp_header_t test_arp;
        test_arp.hardware_type = __builtin_bswap16(1);      // Ethernet
        test_arp.protocol_type = __builtin_bswap16(0x0800); // IPv4
        test_arp.hardware_length = 6;
        test_arp.protocol_length = 4;
        test_arp.operation = __builtin_bswap16(1);          // Request

        test_arp.sender_mac = iface->mac_addr;
        test_arp.sender_ip = iface->ip_addr;

        for (int i = 0; i < 6; i++) test_arp.target_mac.addr[i] = 0;
        test_arp.target_ip = iface->gateway;

        mac_address_t broadcast_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
        bool tx_success = network_interface_send_ethernet_frame(iface, &broadcast_mac,
                                                            0x0806, &test_arp, sizeof(test_arp));

        terminal_write_string("   Manual ARP transmission: ");
        if (tx_success) {
            terminal_set_color(10, 0);
            terminal_write_string("SUCCESS");
            terminal_set_color(7, 0);
        } else {
            terminal_set_color(12, 0);
            terminal_write_string("FAILED");
            terminal_set_color(7, 0);
        }
        terminal_write_string("\n");

        terminal_write_string("\n3. Testing Packet Reception:\n");
        terminal_write_string("   Processing incoming packets for 3 seconds...\n");

        uint32_t initial_rx = iface->rx_packets;
        uint32_t initial_tx = iface->tx_packets;

        uint32_t rx_start = get_system_time();
        while (get_system_time() - rx_start < RX_TEST_MS) network_poll();

        uint32_t final_rx = iface->rx_packets;
        uint32_t final_tx = iface->tx_packets;

        terminal_write_string("   RX packets: ");
        terminal_write_uint(initial_rx);
        terminal_write_string(" to ");
        terminal_write_uint(final_rx);
        terminal_write_string(" (delta: ");
        terminal_write_uint(final_rx - initial_rx);
        terminal_write_string(")\n");

        terminal_write_string("   TX packets: ");
        terminal_write_uint(initial_tx);
        terminal_write_string(" to ");
        terminal_write_uint(final_tx);
        terminal_write_string(" (delta: ");
        terminal_write_uint(final_tx - initial_tx);
        terminal_write_string(")\n");

        terminal_write_string("\n4. RTL8139 Hardware Status:\n");
        if (iface->driver_data) {
            rtl8139_device_t* device = (rtl8139_device_t*)iface->driver_data;
            rtl8139_dump_status(device);
        } else {
            terminal_write_string("   No driver data available\n");
        }

        terminal_write_string("\n5. Network Stack Statistics:\n");
        network_statistics_t* stats = network_get_statistics();
        terminal_write_string("   IP packets sent: ");
        terminal_write_uint((uint32_t)stats->ip_packets_sent);
        terminal_write_string("\n");
        terminal_write_string("   IP packets received: ");
        terminal_write_uint((uint32_t)stats->ip_packets_received);
        terminal_write_string("\n");
        terminal_write_string("   ARP requests sent: ");
        terminal_write_uint((uint32_t)stats->arp_requests_sent);
        terminal_write_string("\n");
        terminal_write_string("   ARP replies received: ");
        terminal_write_uint((uint32_t)stats->arp_replies_received);
        terminal_write_string("\n");

        terminal_write_string("\n6. Result:\n");
        if (final_rx == initial_rx) {
            print_network_error("no packets received during this run", 0, NULL);
        }
        print_network_result(iface);

    } else if (string_compare(args[0], "arptest") == 0) {
        terminal_write_string("\nDirect ARP Test\n");
        terminal_write_string("===============\n");

        network_interface_t* iface = network_interface_get_default();
        if (!iface || iface->ip_addr.addr == 0) {
            terminal_write_string("No interface or IP configured\n");
            return;
        }

        terminal_write_string("Sending ARP request for gateway ");
        char gw_str[16];
        ip_address_to_string(&iface->gateway, gw_str);
        terminal_write_string(gw_str);
        terminal_write_string("...\n");

        arp_send_request(iface, &iface->gateway);

        terminal_write_string("ARP request sent. Processing responses for 5 seconds...\n");

        for (int i = 0; i < 50; i++) {
            network_interface_process_incoming_packets();

            arp_table_entry_t* entry = arp_find_entry(&iface->gateway);
            if (entry && entry->is_valid) {
                terminal_set_color(10, 0);
                terminal_write_string("SUCCESS: Got ARP reply\n");
                terminal_set_color(7, 0);

                char mac_str[18];
                mac_address_to_string(&entry->mac_addr, mac_str);
                terminal_write_string("Gateway MAC: ");
                terminal_write_string(mac_str);
                terminal_write_string("\n");
                return;
            }

            for (volatile int j = 0; j < 100000; j++) {
                __asm__ volatile("pause");
            }
        }

        terminal_set_color(12, 0);
        terminal_write_string("TIMEOUT: No ARP reply received\n");
        terminal_set_color(7, 0);

    } else if (string_compare(args[0], "pcilist") == 0) {
        terminal_write_string("\nPCI Device Listing:\n");
        pci_scan_all_devices();

    } else if (string_compare(args[0], "hwdiag") == 0) {
        terminal_write_string("\nHardware Network Diagnostic:\n");
        network_manager_dump_interface_info();

    } else if (string_compare(args[0], "driverinfo") == 0) {
        command_driverinfo();

    } else if (string_compare(args[0], "networkfix") == 0) {
        command_networkfix();

    } else if (string_compare(args[0], "netdetect") == 0) {
        terminal_write_string("\nNetwork Hardware Detection:\n");
        terminal_write_string("============================\n");

        pci_network_device_t network_devices[8];
        uint32_t device_count = 0;

        if (pci_find_network_devices(network_devices, 8, &device_count)) {
            terminal_write_string("Found ");
            terminal_write_uint(device_count);
            terminal_write_string(" network device(s):\n\n");

            for (uint32_t i = 0; i < device_count; i++) {
                terminal_write_string("Device ");
                terminal_write_uint(i + 1);
                terminal_write_string(":\n");
                terminal_write_string("  Name: ");
                terminal_write_string(network_devices[i].vendor_name);
                terminal_write_string(" ");
                terminal_write_string(network_devices[i].device_name);
                terminal_write_string("\n");
                terminal_write_string("  PCI ID: ");
                terminal_write_hex(network_devices[i].vendor_id);
                terminal_write_string(":");
                terminal_write_hex(network_devices[i].device_id);
                terminal_write_string("\n");
                terminal_write_string("  Location: ");
                terminal_write_uint(network_devices[i].bus);
                terminal_write_string(":");
                terminal_write_uint(network_devices[i].device);
                terminal_write_string(":");
                terminal_write_uint(network_devices[i].function);
                terminal_write_string("\n");

                terminal_write_string("  Driver: ");
                pci_device_t dev = {
                    .bus = network_devices[i].bus, .device = network_devices[i].device,
                    .function = network_devices[i].function, .vendor_id = network_devices[i].vendor_id,
                    .device_id = network_devices[i].device_id, .class_code = PCI_CLASS_NETWORK
                };
                print_driver_status(&dev);
                terminal_write_string("\n\n");
            }

        } else {
            terminal_set_color(12, 0);
            terminal_write_string("No network devices found\n");
            terminal_set_color(7, 0);
        }

    } else if (string_compare(args[0], "secaudit") == 0) {
        command_security_audit(sub_args, sub_argc);
    } else if (string_compare(args[0], "firewall") == 0) {
        command_firewall(sub_args, sub_argc);
    } else if (string_compare(args[0], "ratelimit") == 0) {
        command_ratelimit(sub_args, sub_argc);
    } else if (string_compare(args[0], "secureboot") == 0) {
        command_secureboot(sub_args, sub_argc);
    } else if (string_compare(args[0], "crypto") == 0) {
        command_crypto(sub_args, sub_argc);
    } else if (string_compare(args[0], "security") == 0) {
        command_security_status(sub_args, sub_argc);

    } else if (string_compare(args[0], "aplay") == 0) {
        if (argc > 1) {
            // Build arguments string from remaining args
            char arg_string[512] = {0};
            uint32_t pos = 0;
            for (uint32_t i = 1; i < argc && pos < 500; i++) {
                if (i > 1) {
                    arg_string[pos++] = ' ';
                }
                uint32_t arg_len = 0;
                while (args[i][arg_len] && pos < 500) {
                    arg_string[pos++] = args[i][arg_len++];
                }
            }
            arg_string[pos] = '\0';
            command_aplay(arg_string);
        } else {
            command_aplay("");
        }

    } else if (string_compare(args[0], "amixer") == 0) {
        if (argc > 1) {
            char arg_string[256] = {0};
            uint32_t pos = 0;
            for (uint32_t i = 1; i < argc && pos < 250; i++) {
                if (i > 1) {
                    arg_string[pos++] = ' ';
                }
                uint32_t arg_len = 0;
                while (args[i][arg_len] && pos < 250) {
                    arg_string[pos++] = args[i][arg_len++];
                }
            }
            arg_string[pos] = '\0';
            command_amixer(arg_string);
        } else {
            command_amixer("");
        }

    } else if (string_compare(args[0], "audioinfo") == 0) {
        command_audioinfo();

    } else if (string_compare(args[0], "audiotone") == 0) {
        if (argc > 1) {
            char arg_string[128] = {0};
            uint32_t pos = 0;
            for (uint32_t i = 1; i < argc && pos < 120; i++) {
                if (i > 1) {
                    arg_string[pos++] = ' ';
                }
                uint32_t arg_len = 0;
                while (args[i][arg_len] && pos < 120) {
                    arg_string[pos++] = args[i][arg_len++];
                }
            }
            arg_string[pos] = '\0';
            command_audiotone(arg_string);
        } else {
            command_audiotone("");
        }

    } else if (string_compare(args[0], "audiotest") == 0) {
        command_audiotest();

    } else if (string_compare(args[0], "lsaudio") == 0) {
        command_aplay_list();

    } else if (string_compare(args[0], "acc") == 0) {
        if (argc < 2) {
            terminal_write_string("\nApollo C Compiler\n");
            terminal_write_string("Usage: acc [options] <source.c> <output>\n");
            terminal_write_string("       acc -native <source.c> <output>\n");
            terminal_write_string("       acc -version\n");
            terminal_write_string("       acc -help\n");
            terminal_write_string("\nOptions:\n");
            terminal_write_string("  -native     Write an x86_64 ELF program, run it with run\n");
            terminal_write_string("  -version    Show compiler version\n");
            terminal_write_string("  -help       Show this help message\n\n");
            terminal_write_string("Example: acc /home/sample.c /home/sample.o\n");
        } else if (string_compare(args[1], "-version") == 0) {
            terminal_write_string("\n");
            acc_print_version();
        } else if (string_compare(args[1], "-help") == 0) {
            terminal_write_string("\nApollo C Compiler Help\n");
            terminal_write_string("======================\n\n");
            terminal_write_string("The acc compiler translates C source code into executable bytecode.\n\n");
            terminal_write_string("Basic usage:\n");
            terminal_write_string("  acc source.c output.o    Compile source.c to output.o\n\n");
            terminal_write_string("Supported C subset:\n");
            terminal_write_string("  - int, char, void, FILE and pointers, all 32 bit values\n");
            terminal_write_string("  - globals, locals and one dimensional int arrays\n");
            terminal_write_string("  - functions with parameters and recursion\n");
            terminal_write_string("  - if, else, while, for, break, continue, return\n");
            terminal_write_string("  - all C operators except pointer arithmetic and comma\n");
            terminal_write_string("  - printf putchar puts getchar exit fopen fclose fprintf fputs\n");
            terminal_write_string("  - #define of a number or string, #include lines are skipped\n");
            terminal_write_string("Not supported: structs, unions, floats, pointer arithmetic\n\n");
        } else if (argc >= 3) {
            bool native = string_compare(args[1], "-native") == 0;
            const char* source = native ? args[2] : args[1];
            const char* output = native ? args[3] : args[2];
            terminal_write_string("\n");
            terminal_set_color(11, 0);
            terminal_write_string("Compiling: ");
            terminal_set_color(7, 0);
            terminal_write_string(source);
            terminal_write_string("\n");

            compile_result_t result = (native && argc < 4) ? COMPILE_ERROR_FILE
                                    : native ? acc_compile_file_native(source, output) : acc_compile_file(source, output);

            if (native && argc < 4) {
                terminal_write_string("Usage: acc -native <source.c> <output>\n");
            } else if (result == COMPILE_SUCCESS) {
                terminal_set_color(10, 0);
                terminal_write_string("Success ");
                terminal_set_color(7, 0);
                terminal_write_string("Output: ");
                terminal_write_string(output);
                terminal_write_string("\n");
            } else {
                terminal_set_color(12, 0);
                terminal_write_string("Compilation failed: ");
                terminal_set_color(7, 0);
                terminal_write_string(acc_get_error_message());
                terminal_write_string("\n");
            }
        }

    } else if (string_compare(args[0], "abuild") == 0) {
        const char* target = (argc > 1) ? args[1] : NULL;
        const char* buildfile_path = "/home/buildfile";

        buildfile_t buildfile;
        build_result_t result = abuild_load_buildfile(buildfile_path, &buildfile);

        if (result != BUILD_SUCCESS) {
            terminal_write_string("\n");
            terminal_set_color(12, 0);
            terminal_write_string("Error: ");
            terminal_write_string(abuild_get_error_message(&buildfile));
            terminal_write_string("\n");
            terminal_set_color(7, 0);
            terminal_write_string("\nCreate a buildfile at /home/buildfile\n");
            terminal_write_string("Example buildfile:\n\n");
            terminal_write_string("# Variables\n");
            terminal_write_string("CC = acc\n");
            terminal_write_string("SRC = /home/sample.c\n");
            terminal_write_string("OUT = /home/sample.o\n\n");
            terminal_write_string("# Default target\n");
            terminal_write_string("all: build\n\n");
            terminal_write_string("build:\n");
            terminal_write_string("\t$(CC) $(SRC) $(OUT)\n");
            terminal_write_string("\techo Build complete\n\n");
            terminal_write_string("clean:\n");
            terminal_write_string("\trm $(OUT)\n");
            terminal_write_string("\techo Cleaned.\n\n");
            return;
        }

        terminal_write_string("\n");
        terminal_set_color(14, 0);
        terminal_write_string("Apollo Build System\n");
        terminal_write_string("===================\n");
        terminal_set_color(7, 0);

        if (!target) {
            result = abuild_build_all(&buildfile);
        } else if (string_compare(target, "clean") == 0) {
            result = abuild_clean(&buildfile);
        } else if (string_compare(target, "targets") == 0 || string_compare(target, "list") == 0) {
            abuild_print_targets(&buildfile);
            return;
        } else {
            result = abuild_execute_target(&buildfile, target);
        }

        terminal_write_string("\n");
        if (result == BUILD_SUCCESS) {
            terminal_set_color(10, 0);
            terminal_write_string("Build successful\n");
            terminal_set_color(7, 0);
        } else {
            terminal_set_color(12, 0);
            terminal_write_string("Build failed: ");
            terminal_write_string(abuild_get_error_message(&buildfile));
            terminal_write_string("\n");
            terminal_set_color(7, 0);
        }

    } else if (string_compare(args[0], "exec") == 0 || string_compare(args[0], "run") == 0) {
        if (argc < 2) {
            terminal_write_string("\nProgram Executor\n");
            terminal_write_string("================\n");
            terminal_write_string("Usage: run <program> [arguments]\n");
            terminal_write_string("       run -bc <program.o>\n\n");
            terminal_write_string("Runs acc programs, static ELF64 programs, PE32+ console programs\n");
            terminal_write_string("and flat binaries named *.bin. Ctrl+C stops a native program.\n");
            terminal_write_string("  -bc    Show acc bytecode dump and disassembly\n");
        } else if (argc >= 2 && string_compare(args[1], "-bc") == 0) {
            if (argc >= 3) {
                executor_show_bytecode(args[2]);
            } else {
                terminal_write_string("\nError: No file specified\n");
                terminal_write_string("Usage: exec -bc <program.o>\n");
            }
        } else if (is_native_program(args[1])) {
            run_native_program(sub_argc, sub_args);
        } else {
            terminal_write_string("\n");
            terminal_set_color(11, 0);
            terminal_write_string("Loading: ");
            terminal_set_color(7, 0);
            terminal_write_string(args[1]);
            terminal_write_string("\n");

            exec_result_t result = executor_execute_file(args[1]);

            if (result != EXEC_SUCCESS) {
                terminal_set_color(12, 0);
                terminal_write_string("\nExecution failed: ");
                terminal_set_color(7, 0);
                terminal_write_string(executor_get_error_message());
                terminal_write_string("\n");
            } else {
                terminal_write_string("\nExit code: ");
                terminal_write_int(executor_get_exit_code());
                terminal_write_string("\n");
            }
        }

    } else if (string_compare(args[0], "reboot") == 0) {
        terminal_write_string("\nRebooting system...\n");
        reboot_machine();

    } else if (string_compare(args[0], "shutdown") == 0) {
        terminal_write_string("\nShutting down Apollo OS...\n");
        terminal_write_string("System halted. Safe to power off.\n");
        __asm__ __volatile__("cli; hlt");

    } else {
        terminal_write_string("\nUnknown command: ");
        terminal_write_string(args[0]);
        terminal_write_string("\nType 'help' for available commands\n");
    }

    terminal_write_string("apollo> ");
}


void command_processor_initialize(void) {
    shell.advanced_mode = false;
    shell.initialized = true;
    shell.commands_executed = 0;
    shell.shell_start_time = 0;
    shell.session_id = 1;
    shell.echo_mode = true;
    initialize_security_subsystems();
    string_copy(shell.current_user, "apollo");


    current_command.length = 0;
    current_command.cursor_position = 0;

    history.count = 0;
    history.write_index = 0;
    history.browse_index = -1;
}

void command_processor_handle_input(uint8_t scan_code) {
    if (scan_code == SCANCODE_PAGE_UP || scan_code == SCANCODE_PAGE_DOWN ||
        (scan_code == SCANCODE_HOME && input_manager_is_ctrl_pressed()) ||
        (scan_code == SCANCODE_END && input_manager_is_ctrl_pressed()) ||
        (scan_code == SCANCODE_UP_ARROW && input_manager_is_ctrl_pressed()) ||
        (scan_code == SCANCODE_DOWN_ARROW && input_manager_is_ctrl_pressed())) {
        terminal_handle_scroll_input(scan_code);
        return;
    }

    if (scan_code == SCANCODE_BACKSPACE) {
        if (current_command.cursor_position > 0) {
            current_command.cursor_position--;
            current_command.length--;
            terminal_backspace();
        }
    } else if (scan_code == SCANCODE_UP_ARROW && !input_manager_is_ctrl_pressed()) {
        browse_history(true);
    } else if (scan_code == SCANCODE_DOWN_ARROW && !input_manager_is_ctrl_pressed()) {
        browse_history(false);
    } else {
        char ascii_char = input_manager_scancode_to_ascii(scan_code);

        if (ascii_char == '\n' || ascii_char == '\r') {
            current_command.buffer[current_command.length] = '\0';
            terminal_write_string("\n");
            execute_command(current_command.buffer);
            current_command.length = 0;
            current_command.cursor_position = 0;
            history.browse_index = -1;
        } else if (ascii_char != 0 && current_command.length < MAX_COMMAND_LENGTH - 1) {
            current_command.buffer[current_command.cursor_position] = ascii_char;
            current_command.cursor_position++;
            current_command.length++;
            if (shell.echo_mode) {
                terminal_write_char(ascii_char);
            }
        }
    }
}

bool command_processor_is_initialized(void) {
    return shell.initialized;
}

uint32_t command_processor_get_commands_executed(void) {
    return shell.commands_executed;
}

const char* command_processor_get_current_user(void) {
    return shell.current_user;
}
#include "abuild.h"
#include "acc_compiler.h"
#include "executor.h"
#include "filesystem.h"
#include "terminal.h"
#include "types.h"

static uint32_t string_length(const char* str) {
    uint32_t len = 0;
    while (str[len] != '\0') len++;
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

static void string_trim(char* str) {
    uint32_t start = 0;
    while (str[start] == ' ' || str[start] == '\t') start++;
    
    uint32_t len = 0;
    while (str[len] != '\0') len++;
    
    uint32_t end = len;
    while (end > start && (str[end - 1] == ' ' || str[end - 1] == '\t' || 
           str[end - 1] == '\r' || str[end - 1] == '\n')) {
        end--;
    }
    
    for (uint32_t i = 0; i < end - start; i++) {
        str[i] = str[start + i];
    }
    str[end - start] = '\0';
}

static void parse_dependencies(const char* dep_str, build_target_t* target) {
    uint32_t pos = 0;
    uint32_t dep_start = 0;
    
    while (dep_str[pos] != '\0' && target->dependency_count < ABUILD_MAX_DEPENDENCIES) {
        while (dep_str[pos] == ' ' || dep_str[pos] == '\t') pos++;
        dep_start = pos;
        
        while (dep_str[pos] != ' ' && dep_str[pos] != '\t' && dep_str[pos] != '\0') {
            pos++;
        }
        
        if (pos > dep_start) {
            uint32_t i = 0;
            for (uint32_t j = dep_start; j < pos && i < 63; j++) {
                target->dependencies[target->dependency_count][i++] = dep_str[j];
            }
            target->dependencies[target->dependency_count][i] = '\0';
            target->dependency_count++;
        }
    }
}

static void substitute_variables(buildfile_t* buildfile, const char* input, char* output) {
    uint32_t in_pos = 0;
    uint32_t out_pos = 0;
    
    while (input[in_pos] != '\0' && out_pos < ABUILD_LINE_LENGTH - 1) {
        if (input[in_pos] == '$' && input[in_pos + 1] == '(') {
            in_pos += 2;
            char var_name[64];
            uint32_t var_pos = 0;
            
            while (input[in_pos] != ')' && input[in_pos] != '\0' && var_pos < 63) {
                var_name[var_pos++] = input[in_pos++];
            }
            var_name[var_pos] = '\0';
            
            if (input[in_pos] == ')') in_pos++;
            
            bool found = false;
            for (uint32_t i = 0; i < buildfile->variable_count; i++) {
                if (string_equals(buildfile->variables[i].name, var_name)) {
                    uint32_t val_len = string_length(buildfile->variables[i].value);
                    for (uint32_t j = 0; j < val_len && out_pos < ABUILD_LINE_LENGTH - 1; j++) {
                        output[out_pos++] = buildfile->variables[i].value[j];
                    }
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                output[out_pos++] = '$';
                output[out_pos++] = '(';
                for (uint32_t j = 0; var_name[j] != '\0' && out_pos < ABUILD_LINE_LENGTH - 1; j++) {
                    output[out_pos++] = var_name[j];
                }
                output[out_pos++] = ')';
            }
        } else {
            output[out_pos++] = input[in_pos++];
        }
    }
    
    output[out_pos] = '\0';
}

void abuild_initialize(void) {
}

build_result_t abuild_load_buildfile(const char* filename, buildfile_t* buildfile) {
    buildfile->target_count = 0;
    buildfile->variable_count = 0;
    buildfile->has_error = false;
    buildfile->default_target[0] = '\0';
    
    if (!filesystem_file_exists(filename)) {
        string_copy(buildfile->error_message, "Buildfile not found");
        buildfile->has_error = true;
        return BUILD_ERROR_FILE_NOT_FOUND;
    }
    
    fs_file_handle_t* handle = filesystem_open_file(filename, false);
    if (!handle) {
        string_copy(buildfile->error_message, "Cannot open buildfile");
        buildfile->has_error = true;
        return BUILD_ERROR_FILE_NOT_FOUND;
    }
    
    char file_content[FS_TOOL_BUFFER_SIZE];
    uint32_t bytes_read = filesystem_read_file(handle, file_content, FS_TOOL_BUFFER_SIZE - 1);
    file_content[bytes_read] = '\0';
    filesystem_close_file(handle);
    
    uint32_t pos = 0;
    char line[ABUILD_LINE_LENGTH];
    build_target_t* current_target = NULL;
    
    while (pos < bytes_read) {
        uint32_t line_pos = 0;
        while (file_content[pos] != '\n' && file_content[pos] != '\0' && 
               line_pos < ABUILD_LINE_LENGTH - 1) {
            line[line_pos++] = file_content[pos++];
        }
        line[line_pos] = '\0';
        if (file_content[pos] == '\n') pos++;
        
        string_trim(line);
        
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        if (line[0] == '\t' || (line[0] == ' ' && line[1] == ' ' && line[2] == ' ' && line[3] == ' ')) {
            if (current_target && current_target->command_count < ABUILD_MAX_COMMANDS) {
                string_trim(line);
                if (string_length(line) > 0) {
                    string_copy(current_target->commands[current_target->command_count], line);
                    current_target->command_count++;
                }
            }
            continue;
        }
        
        uint32_t colon_pos = 0;
        bool has_colon = false;
        while (line[colon_pos] != '\0') {
            if (line[colon_pos] == ':') {
                has_colon = true;
                break;
            }
            colon_pos++;
        }
        
        if (has_colon) {
            if (buildfile->target_count >= ABUILD_MAX_TARGETS) {
                string_copy(buildfile->error_message, "Too many targets");
                buildfile->has_error = true;
                return BUILD_ERROR_PARSE;
            }
            
            current_target = &buildfile->targets[buildfile->target_count];
            buildfile->target_count++;
            
            current_target->dependency_count = 0;
            current_target->command_count = 0;
            
            uint32_t i = 0;
            while (i < colon_pos && i < 63) {
                current_target->name[i] = line[i];
                i++;
            }
            current_target->name[i] = '\0';
            string_trim(current_target->name);
            
            if (buildfile->default_target[0] == '\0') {
                string_copy(buildfile->default_target, current_target->name);
            }
            
            if (colon_pos + 1 < line_pos) {
                parse_dependencies(&line[colon_pos + 1], current_target);
            }
        } else {
            uint32_t eq_pos = 0;
            bool has_eq = false;
            while (line[eq_pos] != '\0') {
                if (line[eq_pos] == '=') {
                    has_eq = true;
                    break;
                }
                eq_pos++;
            }
            
            if (has_eq && buildfile->variable_count < ABUILD_MAX_VARIABLES) {
                build_variable_t* var = &buildfile->variables[buildfile->variable_count];
                buildfile->variable_count++;
                
                uint32_t i = 0;
                while (i < eq_pos && i < 63) {
                    var->name[i] = line[i];
                    i++;
                }
                var->name[i] = '\0';
                string_trim(var->name);
                
                i = 0;
                uint32_t val_start = eq_pos + 1;
                while (line[val_start + i] != '\0' && i < 255) {
                    var->value[i] = line[val_start + i];
                    i++;
                }
                var->value[i] = '\0';
                string_trim(var->value);
            }
        }
    }
    
    return BUILD_SUCCESS;
}

static void report_failure(const char* message, const char* detail) {
    terminal_set_color(12, 0);
    terminal_write_string("  Error: ");
    terminal_write_string(message);
    terminal_write_string(detail);
    terminal_write_string("\n");
    terminal_set_color(7, 0);
}

// Build commands are acc, exec, rm, mkdir, cp and echo
static build_result_t execute_command(const char* command) {
    char cmd_copy[ABUILD_LINE_LENGTH];
    string_copy(cmd_copy, command);
    
    char* args[16];
    uint32_t argc = 0;
    
    uint32_t pos = 0;
    uint32_t arg_start = 0;
    
    while (cmd_copy[pos] != '\0' && argc < 16) {
        while (cmd_copy[pos] == ' ' || cmd_copy[pos] == '\t') pos++;
        arg_start = pos;
        
        while (cmd_copy[pos] != ' ' && cmd_copy[pos] != '\t' && cmd_copy[pos] != '\0') {
            pos++;
        }
        
        if (pos > arg_start) {
            args[argc++] = &cmd_copy[arg_start];
            if (cmd_copy[pos] != '\0') {
                cmd_copy[pos] = '\0';
                pos++;
            }
        }
    }
    
    if (argc == 0) {
        return BUILD_SUCCESS;
    }
    
    if (string_equals(args[0], "acc") && argc >= 3) {
        const char* source = args[1];
        const char* output = args[2];
        
        terminal_write_string("  Compiling: ");
        terminal_write_string(source);
        terminal_write_string(" -> ");
        terminal_write_string(output);
        terminal_write_string("\n");
        
        compile_result_t result = acc_compile_file(source, output);
        if (result != COMPILE_SUCCESS) {
            terminal_set_color(12, 0);
            terminal_write_string("  Error: ");
            terminal_write_string(acc_get_error_message());
            terminal_write_string("\n");
            terminal_set_color(7, 0);
            return BUILD_ERROR_COMMAND_FAILED;
        }
        
        return BUILD_SUCCESS;
    }
    
    if (string_equals(args[0], "rm") && argc >= 2) {
        for (uint32_t i = 1; i < argc; i++) {
            if (filesystem_file_exists(args[i])) {
                filesystem_delete_file(args[i]);
            }
        }
        return BUILD_SUCCESS;
    }
    
    if (string_equals(args[0], "echo")) {
        for (uint32_t i = 1; i < argc; i++) {
            terminal_write_string(args[i]);
            if (i < argc - 1) terminal_write_string(" ");
        }
        terminal_write_string("\n");
        return BUILD_SUCCESS;
    }
    
    if (string_equals(args[0], "exec") && argc >= 2) {
        if (executor_execute_file(args[1]) != EXEC_SUCCESS) {
            report_failure("exec failed: ", executor_get_error_message());
            return BUILD_ERROR_COMMAND_FAILED;
        }
        return BUILD_SUCCESS;
    }

    if (string_equals(args[0], "mkdir") && argc >= 2) {
        if (!filesystem_file_exists(args[1]) && !filesystem_create_directory(args[1])) {
            report_failure("cannot create directory ", args[1]);
            return BUILD_ERROR_COMMAND_FAILED;
        }
        return BUILD_SUCCESS;
    }

    if (string_equals(args[0], "cp") && argc >= 3) {
        if (filesystem_file_exists(args[2])) filesystem_delete_file(args[2]);
        if (!filesystem_copy_file(args[1], args[2])) {
            report_failure("cannot copy ", args[1]);
            return BUILD_ERROR_COMMAND_FAILED;
        }
        return BUILD_SUCCESS;
    }

    report_failure("unknown build command: ", args[0]);
    return BUILD_ERROR_COMMAND_FAILED;
}

build_result_t abuild_execute_target(buildfile_t* buildfile, const char* target_name) {
    build_target_t* target = NULL;
    
    for (uint32_t i = 0; i < buildfile->target_count; i++) {
        if (string_equals(buildfile->targets[i].name, target_name)) {
            target = &buildfile->targets[i];
            break;
        }
    }
    
    if (!target) {
        string_copy(buildfile->error_message, "Target not found: ");
        uint32_t len = string_length(buildfile->error_message);
        uint32_t i = 0;
        while (target_name[i] != '\0' && len + i < 255) {
            buildfile->error_message[len + i] = target_name[i];
            i++;
        }
        buildfile->error_message[len + i] = '\0';
        buildfile->has_error = true;
        return BUILD_ERROR_TARGET_NOT_FOUND;
    }
    
    terminal_set_color(10, 0);
    terminal_write_string("Building target: ");
    terminal_write_string(target->name);
    terminal_write_string("\n");
    terminal_set_color(7, 0);
    
    for (uint32_t i = 0; i < target->dependency_count; i++) {
        build_result_t result = abuild_execute_target(buildfile, target->dependencies[i]);
        if (result != BUILD_SUCCESS) {
            return result;
        }
    }
    
    for (uint32_t i = 0; i < target->command_count; i++) {
        char substituted_cmd[ABUILD_LINE_LENGTH];
        substitute_variables(buildfile, target->commands[i], substituted_cmd);
        
        terminal_set_color(8, 0);
        terminal_write_string("  $ ");
        terminal_write_string(substituted_cmd);
        terminal_write_string("\n");
        terminal_set_color(7, 0);
        
        build_result_t result = execute_command(substituted_cmd);
        if (result != BUILD_SUCCESS) {
            return result;
        }
    }
    
    return BUILD_SUCCESS;
}

build_result_t abuild_build_all(buildfile_t* buildfile) {
    if (buildfile->default_target[0] == '\0') {
        string_copy(buildfile->error_message, "No default target");
        buildfile->has_error = true;
        return BUILD_ERROR_TARGET_NOT_FOUND;
    }
    
    return abuild_execute_target(buildfile, buildfile->default_target);
}

build_result_t abuild_clean(buildfile_t* buildfile) {
    for (uint32_t i = 0; i < buildfile->target_count; i++) {
        if (string_equals(buildfile->targets[i].name, "clean")) {
            return abuild_execute_target(buildfile, "clean");
        }
    }
    
    string_copy(buildfile->error_message, "No clean target defined");
    buildfile->has_error = true;
    return BUILD_ERROR_TARGET_NOT_FOUND;
}

const char* abuild_get_error_message(buildfile_t* buildfile) {
    return buildfile->error_message;
}

void abuild_print_targets(buildfile_t* buildfile) {
    terminal_set_color(14, 0);
    terminal_write_string("\nAvailable targets:\n");
    terminal_set_color(7, 0);
    
    for (uint32_t i = 0; i < buildfile->target_count; i++) {
        terminal_write_string("  ");
        terminal_set_color(11, 0);
        terminal_write_string(buildfile->targets[i].name);
        terminal_set_color(7, 0);
        
        if (buildfile->targets[i].dependency_count > 0) {
            terminal_write_string(" (depends on: ");
            for (uint32_t j = 0; j < buildfile->targets[i].dependency_count; j++) {
                terminal_write_string(buildfile->targets[i].dependencies[j]);
                if (j < buildfile->targets[i].dependency_count - 1) {
                    terminal_write_string(", ");
                }
            }
            terminal_write_string(")");
        }
        terminal_write_string("\n");
    }
}
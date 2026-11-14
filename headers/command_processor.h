#ifndef APOLLO_COMMAND_PROCESSOR_H
#define APOLLO_COMMAND_PROCESSOR_H

#include "types.h"

void command_processor_initialize(void);

void command_processor_handle_input(uint8_t scan_code);

bool command_processor_is_initialized(void);
uint32_t command_processor_get_commands_executed(void);
const char* command_processor_get_current_user(void);

#endif
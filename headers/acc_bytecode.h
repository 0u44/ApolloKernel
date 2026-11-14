#ifndef APOLLO_ACC_BYTECODE_H
#define APOLLO_ACC_BYTECODE_H

#include "types.h"

#define ACC_MAGIC_0 'A'
#define ACC_MAGIC_1 'C'
#define ACC_MAGIC_2 'C'
#define ACC_MAGIC_3 '1'
#define ACC_NATIVE_MAGIC_3 'N'
#define ACC_HEADER_SIZE 20
#define ACC_STRING_TAG 0x80000000u
#define ACC_STRING_MASK 0x7FFFFFFFu

/* header layout, all little endian:
   0 magic "ACC1", 4 entry offset, 8 code size, 12 data size, 16 global slot count */

typedef enum {
    OP_HALT = 0x00,
    OP_PUSH = 0x01,     // i32
    OP_PUSHS = 0x02,    // u32 offset into the data segment
    OP_LDL = 0x03,      // u16 slot
    OP_STL = 0x04,      // u16 slot
    OP_LDG = 0x05,      // u16 slot
    OP_STG = 0x06,      // u16 slot
    OP_LDLI = 0x07,     // u16 slot, u16 length
    OP_STLI = 0x08,     // u16 slot, u16 length
    OP_LDGI = 0x09,     // u16 slot, u16 length
    OP_STGI = 0x0A,     // u16 slot, u16 length
    OP_ADJL = 0x0B,     // u16 slot, i8 delta, u8 post
    OP_ADJG = 0x0C,     // u16 slot, i8 delta, u8 post
    OP_ADJLI = 0x0D,    // u16 slot, u16 length, i8 delta, u8 post
    OP_ADJGI = 0x0E,    // u16 slot, u16 length, i8 delta, u8 post
    OP_ADD = 0x10,
    OP_SUB = 0x11,
    OP_MUL = 0x12,
    OP_DIV = 0x13,
    OP_MOD = 0x14,
    OP_AND = 0x15,
    OP_OR = 0x16,
    OP_XOR = 0x17,
    OP_SHL = 0x18,
    OP_SHR = 0x19,
    OP_EQ = 0x1A,
    OP_NE = 0x1B,
    OP_LT = 0x1C,
    OP_LE = 0x1D,
    OP_GT = 0x1E,
    OP_GE = 0x1F,
    OP_NEG = 0x20,
    OP_NOT = 0x21,
    OP_BNOT = 0x22,
    OP_JMP = 0x30,      // i32 relative to the next instruction
    OP_JZ = 0x31,       // i32 relative
    OP_JNZ = 0x32,      // i32 relative
    OP_CALL = 0x33,     // u32 absolute address, u8 argument count
    OP_ENTER = 0x34,    // u16 local slot count
    OP_RET = 0x35,
    OP_POP = 0x36,
    OP_DUP = 0x37,
    OP_SYS = 0x38       // u8 builtin, u8 argument count
} acc_opcode_t;

typedef enum {
    SYS_PRINTF = 0,
    SYS_PUTCHAR = 1,
    SYS_PUTS = 2,
    SYS_GETCHAR = 3,
    SYS_EXIT = 4,
    SYS_FOPEN = 5,
    SYS_FCLOSE = 6,
    SYS_FPRINTF = 7,
    SYS_FPUTS = 8,
    SYS_COUNT = 9
} acc_builtin_t;

#endif
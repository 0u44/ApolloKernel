#include "cpu.h"
#include "terminal.h"

extern const uint64_t interrupt_stub_table[];
extern uint64_t syscall_kernel_rsp;
extern void syscall_entry(void);

#define GDT_ENTRIES 7
#define GDT_KERNEL_CODE 0x00AF9A000000FFFFULL
#define GDT_KERNEL_DATA 0x00CF92000000FFFFULL
#define GDT_USER_DATA 0x00CFF2000000FFFFULL
#define GDT_USER_CODE 0x00AFFA000000FFFFULL
#define TSS_TYPE_AVAILABLE 0x89ULL
#define IDT_ENTRIES 256
#define IDT_INTERRUPT_GATE 0x8E
#define DOUBLE_FAULT_IST 1
#define STUB_COUNT 48
#define ENTRY_STACK_SIZE 32768
#define FAULT_STACK_SIZE 16384

#define MSR_EFER 0xC0000080
#define MSR_STAR 0xC0000081
#define MSR_LSTAR 0xC0000082
#define MSR_SFMASK 0xC0000084
#define MSR_FS_BASE 0xC0000100
#define MSR_GS_BASE 0xC0000101
#define EFER_SCE (1ULL << 0)
// sysret adds 16 to this base for the user code selector and 8 for user data
#define STAR_USER_BASE 0x10ULL
#define STAR_KERNEL_BASE 0x08ULL

#define PIC1_COMMAND 0x20
#define PIC1_DATA 0x21
#define PIC2_COMMAND 0xA0
#define PIC2_DATA 0xA1
#define PIC_INIT 0x11
#define PIC_8086_MODE 0x01
#define PIC_CASCADE_IRQ 0x04
#define PIC_CASCADE_ID 0x02
#define PIC_EOI 0x20
#define PIC_MASK_ALL 0xFF
#define PIC_MASK_TIMER_ONLY 0xFE
#define PIT_CHANNEL0 0x40
#define PIT_COMMAND 0x43
#define PIT_CHANNEL0_RATE 0x34
#define PIT_FREQUENCY 1193182

typedef struct {
    uint32_t reserved0;
    uint64_t rsp[3];
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap_base;
} PACKED tss_t;

typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} PACKED idt_entry_t;

typedef struct {
    uint16_t limit;
    uint64_t base;
} PACKED descriptor_pointer_t;

static uint64_t gdt[GDT_ENTRIES] ALIGNED(16);
static idt_entry_t idt[IDT_ENTRIES] ALIGNED(16);
static tss_t tss ALIGNED(16);
static uint8_t entry_stack[ENTRY_STACK_SIZE] ALIGNED(16);
static uint8_t fault_stack[FAULT_STACK_SIZE] ALIGNED(16);
static interrupt_handler_t handlers[VECTOR_COUNT];
static uint64_t kernel_cr3;
static volatile uint64_t timer_ticks;

static const char* const exception_names[EXCEPTION_COUNT] = {
    "divide error", "debug", "non-maskable interrupt", "breakpoint", "overflow", "bound range exceeded",
    "invalid opcode", "device not available", "double fault", "coprocessor segment overrun", "invalid TSS",
    "segment not present", "stack segment fault", "general protection fault", "page fault", "reserved",
    "x87 floating point error", "alignment check", "machine check", "SIMD floating point error",
    "virtualization exception", "control protection exception", "reserved", "reserved", "reserved",
    "reserved", "reserved", "reserved", "hypervisor injection", "VMM communication", "security exception",
    "reserved"
};

/* port and register access */

static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
    __asm__ volatile("wrmsr" : : "c"(msr), "a"((uint32_t)value), "d"((uint32_t)(value >> 32)));
}

uint64_t cpu_read_cr2(void) {
    uint64_t value;
    __asm__ volatile("mov %%cr2, %0" : "=r"(value));
    return value;
}

uint64_t cpu_read_cr3(void) {
    uint64_t value;
    __asm__ volatile("mov %%cr3, %0" : "=r"(value));
    return value;
}

void cpu_write_cr3(uint64_t value) {
    __asm__ volatile("mov %0, %%cr3" : : "r"(value) : "memory");
}

uint64_t cpu_kernel_cr3(void) {
    return kernel_cr3;
}

void cpu_set_fs_base(uint64_t base) {
    wrmsr(MSR_FS_BASE, base);
}

void cpu_set_gs_base(uint64_t base) {
    wrmsr(MSR_GS_BASE, base);
}

/* descriptor tables */

static void load_gdt(void) {
    uint64_t base = (uint64_t)(uintptr_t)&tss;
    uint64_t limit = sizeof(tss) - 1;
    gdt[0] = 0;
    gdt[1] = GDT_KERNEL_CODE;
    gdt[2] = GDT_KERNEL_DATA;
    gdt[3] = GDT_USER_DATA;
    gdt[4] = GDT_USER_CODE;
    gdt[5] = (limit & 0xFFFF) | ((base & 0xFFFFFF) << 16) | (TSS_TYPE_AVAILABLE << 40) |
             (((limit >> 16) & 0xF) << 48) | (((base >> 24) & 0xFF) << 56);
    gdt[6] = base >> 32;
    descriptor_pointer_t pointer = {sizeof(gdt) - 1, (uint64_t)(uintptr_t)gdt};
    // The far return reloads CS from the new table
    __asm__ volatile(
        "lgdt %0\n"
        "pushq %1\n"
        "leaq 1f(%%rip), %%rax\n"
        "pushq %%rax\n"
        "lretq\n"
        "1:\n"
        "movw %w2, %%ax\n"
        "movw %%ax, %%ds\n"
        "movw %%ax, %%es\n"
        "movw %%ax, %%ss\n"
        "xorw %%ax, %%ax\n"
        "movw %%ax, %%fs\n"
        "movw %%ax, %%gs\n"
        "ltr %w3\n"
        : : "m"(pointer), "i"(KERNEL_CODE_SELECTOR), "r"(KERNEL_DATA_SELECTOR), "r"(TSS_SELECTOR)
        : "rax", "memory");
}

static void set_gate(uint32_t vector, uint64_t address, uint8_t ist) {
    idt[vector].offset_low = (uint16_t)address;
    idt[vector].selector = KERNEL_CODE_SELECTOR;
    idt[vector].ist = ist;
    idt[vector].type = IDT_INTERRUPT_GATE;
    idt[vector].offset_mid = (uint16_t)(address >> 16);
    idt[vector].offset_high = (uint32_t)(address >> 32);
    idt[vector].reserved = 0;
}

static void load_idt(void) {
    for (uint32_t v = 0; v < STUB_COUNT; v++) {
        set_gate(v, interrupt_stub_table[v], v == EXCEPTION_DOUBLE_FAULT ? DOUBLE_FAULT_IST : 0);
    }
    descriptor_pointer_t pointer = {sizeof(idt) - 1, (uint64_t)(uintptr_t)idt};
    __asm__ volatile("lidt %0" : : "m"(pointer));
}

static void setup_syscall(void) {
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_SCE);
    wrmsr(MSR_STAR, (STAR_USER_BASE << 48) | (STAR_KERNEL_BASE << 32));
    wrmsr(MSR_LSTAR, (uint64_t)(uintptr_t)syscall_entry);
    // Interrupts stay off in the kernel, the kernel is not reentrant
    wrmsr(MSR_SFMASK, RFLAGS_IF);
}

/* legacy interrupt controller and timer */

static void setup_pic_and_timer(void) {
    outb(PIC1_COMMAND, PIC_INIT);
    outb(PIC2_COMMAND, PIC_INIT);
    outb(PIC1_DATA, IRQ_BASE_VECTOR);
    outb(PIC2_DATA, IRQ_BASE_VECTOR + 8);
    outb(PIC1_DATA, PIC_CASCADE_IRQ);
    outb(PIC2_DATA, PIC_CASCADE_ID);
    outb(PIC1_DATA, PIC_8086_MODE);
    outb(PIC2_DATA, PIC_8086_MODE);
    outb(PIC1_DATA, PIC_MASK_ALL);
    outb(PIC2_DATA, PIC_MASK_ALL);
    uint16_t divisor = (uint16_t)(PIT_FREQUENCY / TIMER_HZ);
    outb(PIT_COMMAND, PIT_CHANNEL0_RATE);
    outb(PIT_CHANNEL0, (uint8_t)divisor);
    outb(PIT_CHANNEL0, (uint8_t)(divisor >> 8));
}

// The timer only reaches the CPU while a program runs in ring 3, the kernel keeps IF clear
void cpu_timer_enable(bool enable) {
    outb(PIC1_DATA, enable ? PIC_MASK_TIMER_ONLY : PIC_MASK_ALL);
}

uint64_t cpu_timer_ticks(void) {
    return timer_ticks;
}

interrupt_frame_t* cpu_user_frame(void) {
    return (interrupt_frame_t*)(uintptr_t)(tss.rsp[0] - sizeof(interrupt_frame_t));
}

void cpu_initialize(void) {
    tss.rsp[0] = (uint64_t)(uintptr_t)(entry_stack + ENTRY_STACK_SIZE);
    tss.ist[DOUBLE_FAULT_IST - 1] = (uint64_t)(uintptr_t)(fault_stack + FAULT_STACK_SIZE);
    tss.iomap_base = sizeof(tss);
    syscall_kernel_rsp = tss.rsp[0];
    kernel_cr3 = cpu_read_cr3();
    load_gdt();
    load_idt();
    setup_syscall();
    setup_pic_and_timer();
}

void cpu_set_handler(uint32_t vector, interrupt_handler_t handler) {
    if (vector < VECTOR_COUNT) handlers[vector] = handler;
}

const char* cpu_exception_name(uint64_t vector) {
    return vector < EXCEPTION_COUNT ? exception_names[vector] : "interrupt";
}

/* dispatch */

static void write_register(const char* name, uint64_t value) {
    terminal_write_string(name);
    terminal_write_hex(value);
    terminal_write_string("  ");
}

// A fault in the kernel itself cannot be recovered, show where it happened and stop
static void kernel_panic(interrupt_frame_t* f) {
    terminal_set_color(12, 0);
    terminal_write_string("\nKERNEL FAULT: ");
    terminal_write_string(cpu_exception_name(f->vector));
    terminal_write_string("\n");
    write_register("rip ", f->rip);
    write_register("err ", f->error_code);
    write_register("cr2 ", cpu_read_cr2());
    terminal_write_string("\n");
    write_register("rax ", f->rax);
    write_register("rbx ", f->rbx);
    write_register("rcx ", f->rcx);
    write_register("rdx ", f->rdx);
    terminal_write_string("\n");
    write_register("rsi ", f->rsi);
    write_register("rdi ", f->rdi);
    write_register("rbp ", f->rbp);
    write_register("rsp ", f->rsp);
    terminal_write_string("\nSystem halted\n");
    for (;;) __asm__ volatile("cli; hlt");
}

void interrupt_dispatch(interrupt_frame_t* frame) {
    uint64_t vector = frame->vector;
    if (vector >= IRQ_BASE_VECTOR && vector < IRQ_BASE_VECTOR + 16) {
        if (vector == IRQ_SPURIOUS_VECTOR) return;
        if (vector == IRQ_TIMER_VECTOR) timer_ticks++;
        if (vector >= IRQ_BASE_VECTOR + 8) outb(PIC2_COMMAND, PIC_EOI);
        outb(PIC1_COMMAND, PIC_EOI);
    }
    bool from_user = (frame->cs & 3) == 3;
    if (vector < VECTOR_COUNT && handlers[vector] && (from_user || vector >= EXCEPTION_COUNT)) {
        handlers[vector](frame);
        return;
    }
    if (vector < EXCEPTION_COUNT) kernel_panic(frame);
}
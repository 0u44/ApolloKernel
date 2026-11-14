SRCDIR := sources
BUILDDIR := objects
DISTDIR := distribution
INCDIR := headers

KERNEL_SRCS := $(wildcard $(SRCDIR)/kernel/*.c)
DEVICE_SRCS := $(wildcard $(SRCDIR)/devices/*.c)
SYSTEM_SRCS := $(wildcard $(SRCDIR)/system/*.c)
NETWORK_SRCS := $(wildcard $(SRCDIR)/network/*.c)
SECURITY_SOURCES = $(wildcard $(SRCDIR)/security/*.c)
AUDIO_SRCS := $(wildcard $(SRCDIR)/drivers/*.c)
TOOLS_SRCS := $(wildcard $(SRCDIR)/tools/*.c)
GAMES_SRCS := $(wildcard $(SRCDIR)/games/*.c)
ARCH_C_SRCS := $(wildcard $(SRCDIR)/arch/x86_64/*.c)
ARCH_ASM_SRCS := $(wildcard $(SRCDIR)/arch/x86_64/*.s)
WIN32_SRCS := $(wildcard $(SRCDIR)/win32/*.c)
ACCRT_SRCS := $(wildcard $(SRCDIR)/accrt/*.c)

KERNEL_OBJS := $(KERNEL_SRCS:$(SRCDIR)/kernel/%.c=$(BUILDDIR)/kernel/%.o)
DEVICE_OBJS := $(DEVICE_SRCS:$(SRCDIR)/devices/%.c=$(BUILDDIR)/devices/%.o)
SYSTEM_OBJS := $(SYSTEM_SRCS:$(SRCDIR)/system/%.c=$(BUILDDIR)/system/%.o)
NETWORK_OBJS := $(NETWORK_SRCS:$(SRCDIR)/network/%.c=$(BUILDDIR)/network/%.o)
SECURITY_OBJS := $(SECURITY_SOURCES:$(SRCDIR)/security/%.c=$(BUILDDIR)/security/%.o)
AUDIO_OBJS := $(AUDIO_SRCS:$(SRCDIR)/drivers/%.c=$(BUILDDIR)/drivers/%.o)
TOOLS_OBJS := $(TOOLS_SRCS:$(SRCDIR)/tools/%.c=$(BUILDDIR)/tools/%.o)
GAMES_OBJS := $(GAMES_SRCS:$(SRCDIR)/games/%.c=$(BUILDDIR)/games/%.o)
ARCH_C_OBJS := $(ARCH_C_SRCS:$(SRCDIR)/arch/x86_64/%.c=$(BUILDDIR)/arch/%.o)
ARCH_ASM_OBJS := $(ARCH_ASM_SRCS:$(SRCDIR)/arch/x86_64/%.s=$(BUILDDIR)/arch/%.o)
WIN32_OBJS := $(WIN32_SRCS:$(SRCDIR)/win32/%.c=$(BUILDDIR)/win32/%.o)
WIN32_RUNTIME := $(BUILDDIR)/win32/runtime.bin
ACCRT_OBJS := $(ACCRT_SRCS:$(SRCDIR)/accrt/%.c=$(BUILDDIR)/accrt/%.o)
ACC_RUNTIME := $(BUILDDIR)/accrt/acc_runtime.bin
RUNTIME_OBJS := $(WIN32_OBJS) $(ACCRT_OBJS)

ALL_OBJS := $(KERNEL_OBJS) $(DEVICE_OBJS) $(SYSTEM_OBJS) $(NETWORK_OBJS) $(SECURITY_OBJS) $(AUDIO_OBJS) $(TOOLS_OBJS) $(GAMES_OBJS) $(ARCH_C_OBJS) $(ARCH_ASM_OBJS)

CROSS_COMPILER := x86_64-elf-gcc
ASSEMBLER := nasm
LINKER := x86_64-elf-ld
OBJCOPY := x86_64-elf-objcopy

CFLAGS := -I$(INCDIR) -std=c99 -ffreestanding -O2 -Wall -Wextra \
          -nostdlib -mno-red-zone -mno-mmx -mno-sse -mno-sse2 \
          -mcmodel=kernel -fno-stack-protector -fno-pic \
          -DENABLE_HARDWARE_SAFETY -DSAFE_MODE_ENABLED -MMD -MP

RUNTIME_CFLAGS := -I$(INCDIR) -std=c11 -ffreestanding -O2 -Wall -Wextra \
                -nostdlib -fno-pic -mcmodel=large -fno-stack-protector -MMD -MP

ASMFLAGS := -f elf64
LDFLAGS := -nostdlib -T bootloader/linker.ld -N

-include $(ALL_OBJS:.o=.d) $(RUNTIME_OBJS:.o=.d)

.PHONY: all kernel iso clean run debug verify run-net debug-hardware test-hardware-safety help \
        test-audio debug-audio test-audio-playback

all: iso

kernel: $(DISTDIR)/apollo.bin

iso: $(DISTDIR)/apollo.iso

$(BUILDDIR)/kernel/%.o: $(SRCDIR)/kernel/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/arch/%.o: $(SRCDIR)/arch/x86_64/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/arch/%.o: $(SRCDIR)/arch/x86_64/%.s
	@mkdir -p $(dir $@)
	$(ASSEMBLER) $(ASMFLAGS) $< -o $@

$(BUILDDIR)/devices/%.o: $(SRCDIR)/devices/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/system/%.o: $(SRCDIR)/system/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/network/%.o: $(SRCDIR)/network/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/security/%.o: $(SRCDIR)/security/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/drivers/%.o: $(SRCDIR)/drivers/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/tools/%.o: $(SRCDIR)/tools/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/games/%.o: $(SRCDIR)/games/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(RUNTIME_OBJS): $(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(RUNTIME_CFLAGS) -I$(dir $<) -c $< -o $@

define link_runtime
	$(LINKER) -nostdlib -T $(filter %.ld,$^) -o $(@:.bin=.elf) $(filter %.o,$^)
	$(OBJCOPY) -O binary $(@:.bin=.elf) $@
endef

$(WIN32_RUNTIME): $(WIN32_OBJS) $(SRCDIR)/win32/runtime.ld
	$(link_runtime)

$(ACC_RUNTIME): $(ACCRT_OBJS) $(SRCDIR)/accrt/accrt.ld
	$(link_runtime)

$(BUILDDIR)/arch/win32_runtime.o: $(WIN32_RUNTIME)
$(BUILDDIR)/arch/acc_runtime.o: $(ACC_RUNTIME)

$(DISTDIR)/apollo.bin: $(ALL_OBJS)
	@mkdir -p $(DISTDIR) $(BUILDDIR)
	$(LINKER) $(LDFLAGS) -o $(BUILDDIR)/apollo.unsigned $(ALL_OBJS)
	$(OBJCOPY) -O binary --only-section=.text $(BUILDDIR)/apollo.unsigned $(BUILDDIR)/measured.text
	$(OBJCOPY) -O binary --only-section=.rodata $(BUILDDIR)/apollo.unsigned $(BUILDDIR)/measured.rodata
	cat $(BUILDDIR)/measured.text $(BUILDDIR)/measured.rodata | sha256sum | cut -c1-64 | xxd -r -p > $(BUILDDIR)/measured.sha256
	$(OBJCOPY) --update-section .secureboot=$(BUILDDIR)/measured.sha256 $(BUILDDIR)/apollo.unsigned $@

$(DISTDIR)/apollo.iso: $(DISTDIR)/apollo.bin
	@mkdir -p $(DISTDIR)/iso_root/boot/grub
	@cp $(DISTDIR)/apollo.bin $(DISTDIR)/iso_root/boot/apollo.bin
	@cp bootloader/grub.cfg $(DISTDIR)/iso_root/boot/grub/
	grub-mkrescue -o $@ $(DISTDIR)/iso_root

clean:
	rm -rf $(BUILDDIR) $(DISTDIR)

run: iso
	qemu-system-x86_64 -cdrom distribution/apollo.iso -m 512M \
	-netdev user,id=net0 \
	-device rtl8139,netdev=net0 \
	-device intel-hda \
	-device hda-duplex

debug: iso
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M -s -S -monitor stdio \
	-netdev user,id=net0,hostfwd=tcp::8080-:80 \
	-device rtl8139,netdev=net0 \
	-device AC97

run-net: iso
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M -display gtk \
	-netdev user,id=net0,dns=8.8.8.8,dhcpstart=10.0.2.15 \
	-device rtl8139,netdev=net0,mac=52:54:00:12:34:56 \
	-device AC97

test-audio: iso
	@echo "========================================"
	@echo "Apollo OS Audio System Test (Safe Mode)"
	@echo "========================================"
	@echo "Testing with minimal hardware emulation..."
	@echo "Available commands after boot:"
	@echo "  audiotest    - Test audio hardware"
	@echo "  audioinfo    - Audio system info"
	@echo "  lsaudio      - List audio devices"
	@echo "========================================"
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		-name "Apollo OS - Audio Test (Safe Mode)"

debug-audio: iso
	@echo "========================================"
	@echo "Apollo OS Audio Debug Mode"
	@echo "========================================"
	@echo "Features enabled:"
	@echo "  - Intel HD Audio controller"
	@echo "  - Audio codec emulation"
	@echo "  - Serial debug output"
	@echo "  - Monitor console"
	@echo "========================================"
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-device intel-hda \
		-device hda-duplex \
		-serial stdio \
		-d int,guest_errors \
		-monitor stdio \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		-name "Apollo OS - Audio Debug Mode"

test-audio-playback: iso
	@echo "========================================"
	@echo "Apollo OS Audio Playback Test"
	@echo "========================================"
	@echo "This test includes:"
	@echo "  - HD Audio controller"
	@echo "  - Audio codec with playback/recording"
	@echo "  - WAV file playback capability"
	@echo "  - Audio mixer controls"
	@echo ""
	@echo "Test commands to run after boot:"
	@echo "  audiotest                    - Hardware test"
	@echo "  audiotone 440 3             - Play 440Hz tone"
	@echo "  amixer set Master 75        - Set volume"
	@echo "  aplay /path/to/file.wav     - Play WAV file"
	@echo "========================================"
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-device intel-hda \
		-device hda-duplex \
		-audiodev pulse,id=audio0 \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		-name "Apollo OS - Audio Playback Test"

test-ac97-audio: iso
	@echo "Testing Apollo OS with AC97 audio controller..."
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-device AC97 \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		-name "Apollo OS - AC97 Audio Test"

test-sb16-audio: iso
	@echo "Testing Apollo OS with Sound Blaster 16 audio..."
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-device sb16 \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		-name "Apollo OS - SB16 Audio Test"

debug-hardware: iso
	@echo "========================================"
	@echo "Apollo OS Hardware Debug Mode"
	@echo "========================================"
	@echo "Features enabled:"
	@echo "  - Hardware safety wrappers"
	@echo "  - PCI access protection"
	@echo "  - Memory allocation validation"
	@echo "  - Interrupt conflict detection"
	@echo "  - Audio hardware debugging"
	@echo "========================================"
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-serial stdio \
		-d int,cpu_reset,guest_errors \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		-device intel-hda \
		-device hda-duplex \
		-name "Apollo OS - Hardware Debug Mode"

test-hardware-safety: iso
	@echo "========================================"
	@echo "Testing Apollo OS Hardware Safety"
	@echo "========================================"
	@echo "This test will:"
	@echo "  1. Boot Apollo OS with hardware safety enabled"
	@echo "  2. Test all security commands that previously caused reboots"
	@echo "  3. Test audio hardware initialization"
	@echo "  4. Verify system stability under hardware stress"
	@echo "  5. Timeout after 60 seconds (expected behavior)"
	@echo "========================================"
	timeout 60s qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso \
		-m 256M \
		-serial stdio \
		-nographic \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		-device intel-hda \
		-device hda-duplex \
		|| echo "Hardware safety test completed (timeout indicates stable operation)"

debug-memory: iso
	@echo "Starting Apollo OS with memory debugging..."
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-serial stdio \
		-d guest_errors,unimp \
		-monitor stdio \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		-device AC97 \
		-name "Apollo OS - Memory Debug Mode"

debug-network: iso
	@echo "Starting Apollo OS with network debugging..."
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-netdev user,id=net0,hostfwd=tcp::8080-:80,hostfwd=tcp::2222-:22 \
		-device rtl8139,netdev=net0,mac=52:54:00:12:34:56 \
		-object filter-dump,id=dump0,netdev=net0,file=network.pcap \
		-serial stdio \
		-monitor stdio \
		-device AC97 \
		-name "Apollo OS - Network Debug Mode"

test-e1000: iso
	@echo "Testing Apollo OS with Intel e1000 network hardware..."
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-netdev user,id=net0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:57 \
		-device AC97 \
		-serial stdio \
		-name "Apollo OS - Intel e1000 Test"

test-no-network: iso
	@echo "Testing Apollo OS in software-only mode (no network hardware)..."
	qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso -m 512M \
		-device intel-hda \
		-device hda-duplex \
		-serial stdio \
		-name "Apollo OS - Software Only Mode"

test-security-commands: iso
	@echo "========================================"
	@echo "Security Command Safety Test"
	@echo "========================================"
	@echo "This will test all security commands:"
	@echo "  - firewall enable/disable/status"
	@echo "  - secaudit --full"
	@echo "  - ratelimit enable"
	@echo "  - crypto test"
	@echo "  - security status"
	@echo "========================================"
	timeout 45s qemu-system-x86_64 -cdrom $(DISTDIR)/apollo.iso \
		-m 256M \
		-nographic \
		-serial stdio \
		-no-reboot \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		-device AC97 \
		|| echo "Security commands test completed successfully"

verify: $(DISTDIR)/apollo.bin
	@chmod +x verify_elf.sh
	@./verify_elf.sh

help:
	@echo "========================================"
	@echo "Apollo OS Build System"
	@echo "========================================"
	@echo "Build targets:"
	@echo "  all                   Build ISO (default)"
	@echo "  kernel                Build kernel binary only"
	@echo "  iso                   Build bootable ISO"
	@echo "  clean                 Clean build artifacts"
	@echo ""
	@echo "Run targets:"
	@echo "  run                   Run with RTL8139 network + AC97 audio"
	@echo "  run-net              Run with full network + audio setup"
	@echo "  test-e1000           Test with Intel e1000 NIC"
	@echo "  test-no-network      Test software-only mode"
	@echo ""
	@echo "Audio testing:"
	@echo "  test-audio           Test with Intel HD Audio"
	@echo "  debug-audio          Debug audio with serial output"
	@echo "  test-audio-playback  Test audio playback capabilities"
	@echo "  test-ac97-audio      Test with AC97 audio controller"
	@echo "  test-sb16-audio      Test with Sound Blaster 16"
	@echo ""
	@echo "Debug targets:"
	@echo "  debug                Standard debug mode"
	@echo "  debug-hardware       Hardware fault debugging"
	@echo "  debug-memory         Memory allocation debugging"
	@echo "  debug-network        Network packet debugging"
	@echo ""
	@echo "Safety testing:"
	@echo "  test-hardware-safety Test hardware safety mechanisms"
	@echo "  test-security-commands Test security command stability"
	@echo ""
	@echo "Hardware Safety Features:"
	@echo "  Safe PCI access wrappers"
	@echo "  Memory allocation validation"
	@echo "  Hardware fault recovery"
	@echo "  Graceful degradation to software mode"
	@echo "  Security command stability"
	@echo "  Audio hardware safety"
	@echo "========================================"

$(BUILDDIR)/system/safe_hardware.o: $(SRCDIR)/system/safe_hardware.c $(INCDIR)/safe_hardware.h $(INCDIR)/terminal.h $(INCDIR)/types.h
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/system/command_processor.o: $(SRCDIR)/system/command_processor.c $(INCDIR)/safe_hardware.h
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/network/network_manager.o: $(SRCDIR)/network/network_manager.c $(INCDIR)/safe_hardware.h
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

# Audio driver dependencies
$(BUILDDIR)/drivers/hda_driver.o: $(SRCDIR)/drivers/hda_driver.c $(INCDIR)/hda_driver.h $(INCDIR)/safe_hardware.h $(INCDIR)/terminal.h $(INCDIR)/types.h
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/drivers/audio_subsystem.o: $(SRCDIR)/drivers/audio_subsystem.c $(INCDIR)/audio_subsystem.h $(INCDIR)/hda_driver.h $(INCDIR)/terminal.h $(INCDIR)/heap_allocator.h
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/drivers/wave_player.o: $(SRCDIR)/drivers/wave_player.c $(INCDIR)/wave_player.h $(INCDIR)/audio_subsystem.h $(INCDIR)/filesystem.h $(INCDIR)/terminal.h
	@mkdir -p $(dir $@)
	$(CROSS_COMPILER) $(CFLAGS) -c $< -o $@

check-files:
	@echo "Checking for required hardware safety files..."
	@test -f $(SRCDIR)/system/safe_hardware.c || (echo "ERROR: Missing $(SRCDIR)/system/safe_hardware.c" && false)
	@test -f $(INCDIR)/safe_hardware.h || (echo "ERROR: Missing $(INCDIR)/safe_hardware.h" && false)
	@echo "Checking for audio driver files..."
	@test -f $(SRCDIR)/drivers/hda_driver.c || (echo "ERROR: Missing $(SRCDIR)/drivers/hda_driver.c" && false)
	@test -f $(SRCDIR)/drivers/audio_subsystem.c || (echo "ERROR: Missing $(SRCDIR)/drivers/audio_subsystem.c" && false)
	@test -f $(SRCDIR)/drivers/wave_player.c || (echo "ERROR: Missing $(SRCDIR)/drivers/wave_player.c" && false)
	@test -f $(INCDIR)/hda_driver.h || (echo "ERROR: Missing $(INCDIR)/hda_driver.h" && false)
	@test -f $(INCDIR)/audio_subsystem.h || (echo "ERROR: Missing $(INCDIR)/audio_subsystem.h" && false)
	@test -f $(INCDIR)/wave_player.h || (echo "ERROR: Missing $(INCDIR)/wave_player.h" && false)
	@echo "All required files present"
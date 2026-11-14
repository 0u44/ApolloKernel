#include "time_keeper.h"
#include "types.h"

#define CMOS_ADDRESS_PORT 0x70
#define CMOS_DATA_PORT 0x71

#define RTC_SECONDS 0x00
#define RTC_MINUTES 0x02
#define RTC_HOURS 0x04
#define RTC_DAY 0x07
#define RTC_MONTH 0x08
#define RTC_YEAR 0x09
#define RTC_CENTURY 0x32
#define RTC_STATUS_A 0x0A
#define RTC_STATUS_B 0x0B
#define RTC_STATUS_C 0x0C

#define PIT_FREQUENCY 1193182
#define PIT_CHANNEL2_PORT 0x42
#define PIT_COMMAND_PORT 0x43
#define PIT_GATE_PORT 0x61
#define PIT_CHANNEL2_ONESHOT 0xB0
#define PIT_GATE_ENABLE 0x01
#define PIT_SPEAKER_ENABLE 0x02
#define PIT_OUTPUT_HIGH 0x20
#define CALIBRATION_MS 10
#define CALIBRATION_SPIN_LIMIT 100000000ULL
#define MS_PER_SECOND 1000
#define US_PER_MS 1000
#define NS_PER_MS 1000000ULL
#define SECONDS_PER_DAY 86400

static uint64_t tsc_per_ms = 0;
static uint64_t boot_tsc = 0;

static inline void outb(uint16_t port, uint8_t data) {
    __asm__ volatile("outb %0, %1" : : "a"(data), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t result;
    __asm__ volatile("inb %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static uint8_t read_rtc_register(uint8_t reg) {
    outb(CMOS_ADDRESS_PORT, reg);
    return inb(CMOS_DATA_PORT);
}

static int bcd_to_binary(uint8_t bcd_value) {
    return ((bcd_value >> 4) * 10) + (bcd_value & 0x0F);
}

static bool rtc_update_in_progress(void) {
    return (read_rtc_register(RTC_STATUS_A) & 0x80) != 0;
}

void time_keeper_get_datetime(int* year, int* month, int* day, int* hour, int* minute, int* second) {
    uint8_t century;
    uint8_t last_second, last_minute, last_hour, last_day, last_month, last_year, last_century;

    while (rtc_update_in_progress()) {
        __asm__ volatile("pause");
    }

    *second = read_rtc_register(RTC_SECONDS);
    *minute = read_rtc_register(RTC_MINUTES);
    *hour = read_rtc_register(RTC_HOURS);
    *day = read_rtc_register(RTC_DAY);
    *month = read_rtc_register(RTC_MONTH);
    *year = read_rtc_register(RTC_YEAR);
    century = read_rtc_register(RTC_CENTURY);

    do {
        last_second = *second;
        last_minute = *minute;
        last_hour = *hour;
        last_day = *day;
        last_month = *month;
        last_year = *year;
        last_century = century;

        while (rtc_update_in_progress()) {
            __asm__ volatile("pause");
        }

        *second = read_rtc_register(RTC_SECONDS);
        *minute = read_rtc_register(RTC_MINUTES);
        *hour = read_rtc_register(RTC_HOURS);
        *day = read_rtc_register(RTC_DAY);
        *month = read_rtc_register(RTC_MONTH);
        *year = read_rtc_register(RTC_YEAR);
        century = read_rtc_register(RTC_CENTURY);

    } while ((last_second != *second) || (last_minute != *minute) ||
             (last_hour != *hour) || (last_day != *day) ||
             (last_month != *month) || (last_year != *year) ||
             (last_century != century));

    uint8_t status_b = read_rtc_register(RTC_STATUS_B);

    if (!(status_b & 0x04)) {
        *second = bcd_to_binary(*second);
        *minute = bcd_to_binary(*minute);
        *hour = bcd_to_binary(*hour);
        *day = bcd_to_binary(*day);
        *month = bcd_to_binary(*month);
        *year = bcd_to_binary(*year);
        century = bcd_to_binary(century);
    }

    if (!(status_b & 0x02) && (*hour & 0x80)) {
        *hour = ((*hour & 0x7F) + 12) % 24;
    }

    if (century != 0) {
        *year += century * 100;
    } else {
        *year += (*year >= 70) ? 1900 : 2000;
    }
}

static inline uint64_t read_tsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

// Counts TSC ticks across a 10 ms one shot on PIT channel 2
static uint64_t calibrate_with_pit(void) {
    uint16_t count = (uint16_t)(PIT_FREQUENCY * CALIBRATION_MS / MS_PER_SECOND);
    uint8_t gate = inb(PIT_GATE_PORT);
    outb(PIT_GATE_PORT, (uint8_t)((gate & ~PIT_SPEAKER_ENABLE) | PIT_GATE_ENABLE));
    outb(PIT_COMMAND_PORT, PIT_CHANNEL2_ONESHOT);
    outb(PIT_CHANNEL2_PORT, (uint8_t)(count & 0xFF));
    outb(PIT_CHANNEL2_PORT, (uint8_t)(count >> 8));

    uint64_t start = read_tsc();
    uint64_t spins = 0;
    while (!(inb(PIT_GATE_PORT) & PIT_OUTPUT_HIGH)) {
        if (++spins > CALIBRATION_SPIN_LIMIT) {
            outb(PIT_GATE_PORT, gate);
            return 0;
        }
    }
    uint64_t elapsed = read_tsc() - start;
    outb(PIT_GATE_PORT, gate);
    return elapsed / CALIBRATION_MS;
}

// Fallback when the PIT never signals, measures one full RTC second
static uint64_t calibrate_with_rtc(void) {
    uint8_t first = read_rtc_register(RTC_SECONDS);
    while (read_rtc_register(RTC_SECONDS) == first) {
        __asm__ volatile("pause");
    }
    uint64_t start = read_tsc();
    uint8_t second = read_rtc_register(RTC_SECONDS);
    while (read_rtc_register(RTC_SECONDS) == second) {
        __asm__ volatile("pause");
    }
    return (read_tsc() - start) / MS_PER_SECOND;
}

void time_keeper_initialize(void) {
    uint8_t status_b = read_rtc_register(RTC_STATUS_B);
    status_b |= 0x02; // 24-hour format
    status_b |= 0x04; // Binary format

    outb(CMOS_ADDRESS_PORT, RTC_STATUS_B);
    outb(CMOS_DATA_PORT, status_b);

    read_rtc_register(RTC_STATUS_C);

    tsc_per_ms = calibrate_with_pit();
    if (tsc_per_ms == 0) {
        tsc_per_ms = calibrate_with_rtc();
    }
    boot_tsc = read_tsc();
}

uint64_t time_keeper_get_uptime_ms(void) {
    if (tsc_per_ms == 0) return 0;
    return (read_tsc() - boot_tsc) / tsc_per_ms;
}

// Split into whole milliseconds and the remainder so the multiply cannot overflow
uint64_t time_keeper_get_uptime_ns(void) {
    if (tsc_per_ms == 0) return 0;
    uint64_t ticks = read_tsc() - boot_tsc;
    return (ticks / tsc_per_ms) * NS_PER_MS + (ticks % tsc_per_ms) * NS_PER_MS / tsc_per_ms;
}

uint64_t time_keeper_get_tsc_per_ms(void) {
    return tsc_per_ms;
}

void time_keeper_delay_us(uint32_t microseconds) {
    if (tsc_per_ms == 0) return;
    uint64_t target = read_tsc() + (tsc_per_ms * microseconds) / US_PER_MS;
    while (read_tsc() < target) {
        __asm__ volatile("pause");
    }
}

void time_keeper_delay_ms(uint32_t milliseconds) {
    time_keeper_delay_us(milliseconds * US_PER_MS);
}

// Days since 1970-01-01 for a proleptic Gregorian date
static int64_t days_from_civil(int year, int month, int day) {
    year -= month <= 2;
    int64_t era = (year >= 0 ? year : year - 399) / 400;
    int64_t yoe = year - era * 400;
    int64_t doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

uint64_t time_keeper_get_unix_time(void) {
    int year, month, day, hour, minute, second;
    time_keeper_get_datetime(&year, &month, &day, &hour, &minute, &second);
    return (uint64_t)days_from_civil(year, month, day) * SECONDS_PER_DAY +
           (uint64_t)hour * 3600 + (uint64_t)minute * 60 + (uint64_t)second;
}

uint64_t time_keeper_get_uptime_seconds(void) {
    return time_keeper_get_uptime_ms() / MS_PER_SECOND;
}

#include "lwip/sys.h"
#include <mach/mach_time.h>

static mach_timebase_info_data_t timebase_info;
static int timebase_initialized = 0;

u32_t sys_now(void) {
    if (!timebase_initialized) {
        mach_timebase_info(&timebase_info);
        timebase_initialized = 1;
    }
    uint64_t ticks = mach_absolute_time();
    /* Convert to milliseconds */
    uint64_t nanos = ticks * timebase_info.numer / timebase_info.denom;
    return (u32_t)(nanos / 1000000ULL);
}

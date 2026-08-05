// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <ratio>

namespace shinku::cache {

// CacheClock is a clock-domain tag, not a clock source. Backends must construct
// CacheTime values from the same monotonic clock used by their Cache Hit Path.
struct CacheClock {
    using rep = int64_t;
    using period = std::nano;
    using duration = std::chrono::nanoseconds;
    using time_point = std::chrono::time_point<CacheClock>;

    static constexpr bool is_steady = true;
};

using CacheTime = CacheClock::time_point;
using CacheLifetime = std::chrono::seconds;

// Timestamp in the CacheClock domain read from the kernel's boot clock
// (CLOCK_BOOTTIME), the same monotonic time domain used by the BPF hit path.
[[nodiscard]] inline CacheTime boot_time() noexcept {
    timespec value {};
    clock_gettime(CLOCK_BOOTTIME, &value);
    return CacheTime(std::chrono::seconds(value.tv_sec) + std::chrono::nanoseconds(value.tv_nsec));
}

} // namespace shinku::cache

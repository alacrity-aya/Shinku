// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <ratio>

namespace shinku::cache {

/**
 * @brief Clock-domain tag for cache timestamps, not a clock source.
 *
 * Backends must construct @ref CacheTime values from the same monotonic clock
 * used by their cache hit path, so that expiry comparisons are consistent
 * across the data plane and the host cleanup loop.
 */
struct CacheClock {
    using rep = int64_t; ///< Representation of the duration count.
    using period = std::nano; ///< Tick period: one nanosecond.
    using duration = std::chrono::nanoseconds; ///< Duration type.
    using time_point = std::chrono::time_point<CacheClock>; ///< Time-point type.

    static constexpr bool is_steady = true; ///< Cache time is monotonic and never decreases.
};

using CacheTime = CacheClock::time_point; ///< A moment in the cache clock domain.
using CacheLifetime = std::chrono::seconds; ///< A cache entry's remaining lifetime in seconds.

/**
 * @brief Read the current time in the @ref CacheClock domain.
 *
 * Reads the kernel's boot clock (CLOCK_BOOTTIME), the same monotonic time
 * domain used by the BPF hit path, so host-side expiry checks line up with
 * the timestamps stamped on the data plane.
 *
 * @return The current @ref CacheTime.
 */
[[nodiscard]] inline CacheTime boot_time() noexcept {
    timespec value {};
    clock_gettime(CLOCK_BOOTTIME, &value);
    return CacheTime(std::chrono::seconds(value.tv_sec) + std::chrono::nanoseconds(value.tv_nsec));
}

} // namespace shinku::cache

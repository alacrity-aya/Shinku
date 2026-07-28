// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <chrono>
#include <cstdint>
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

} // namespace shinku::cache

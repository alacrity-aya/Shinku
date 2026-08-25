// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_time.h"

#include "cache/cache_time.h"

#include <chrono>
#include <ctime>
#include <optional>

namespace shinku::backend::dpdk {

/// Read CLOCK_BOOTTIME into the cache time domain, or return empty if the clock read fails.
std::optional<cache::CacheTime> read_dpdk_boot_time() noexcept {
    timespec value {};
    if (clock_gettime(CLOCK_BOOTTIME, &value) != 0)
        return std::nullopt;
    return cache::CacheTime(std::chrono::seconds(value.tv_sec) + std::chrono::nanoseconds(value.tv_nsec));
}

} // namespace shinku::backend::dpdk

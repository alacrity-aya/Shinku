// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/cache_time.h"

#include <optional>

namespace shinku::backend::dpdk {

/**
 * @brief Read the current time in the @ref cache::CacheClock domain via DPDK.
 *
 * Uses DPDK's time source to produce a value comparable to @ref cache::boot_time
 * so the DPDK cache path and the host cleanup loop share one time domain.
 *
 * @return The current @ref cache::CacheTime, or empty if the clock could not be read.
 */
[[nodiscard]] std::optional<cache::CacheTime> read_dpdk_boot_time() noexcept;

} // namespace shinku::backend::dpdk

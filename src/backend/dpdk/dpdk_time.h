// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/cache_time.h"

#include <optional>

namespace shinku::backend::dpdk {

[[nodiscard]] std::optional<cache::CacheTime> read_dpdk_boot_time() noexcept;

} // namespace shinku::backend::dpdk

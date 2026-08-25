// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/cache/ebpf_cache_storage_layout.h"
#include "ebpf_cache_abi.h"

#include <cstdint>

namespace shinku::backend::ebpf {

/// Configuration handed to the BPF skeleton at open time.
struct EbpfSkeletonConfig {
    EbpfCacheStorageLayout cache_layout; ///< Geometry of the cache arena storage.
    ebpf_cache_secret secret; ///< Secret salting the physical-key fingerprint.
    uint32_t pending_capacity; ///< Maximum number of pending queries.
    uint64_t pending_timeout_ns; ///< Pending-query timeout in nanoseconds since boot.
};

} // namespace shinku::backend::ebpf

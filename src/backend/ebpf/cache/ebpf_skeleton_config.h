// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/cache/ebpf_cache_storage_layout.h"
#include "ebpf_cache_abi.h"

#include <cstdint>

namespace shinku::backend::ebpf {

struct EbpfSkeletonConfig {
    EbpfCacheStorageLayout cache_layout;
    ebpf_cache_secret secret;
    uint32_t pending_capacity;
    uint64_t pending_timeout_ns;
};

} // namespace shinku::backend::ebpf

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "config/config.h"
#include "ebpf_cache_abi.h"

#include <cstddef>
#include <cstdint>

namespace shinku::backend::ebpf {

struct EbpfCacheStorageLayout {
    uint32_t entry_capacity;
    uint32_t response_capacity;
    uint32_t ttl_offset_capacity;
    uint32_t slot_stride;
    size_t required_arena_bytes;
    size_t arena_bytes;
    uint32_t arena_page_count;

    [[nodiscard]] ebpf_cache_bpf_layout bpf_layout() const noexcept;

    bool operator==(const EbpfCacheStorageLayout&) const = default;
};

[[nodiscard]] EbpfCacheStorageLayout
make_ebpf_cache_storage_layout(const config::CacheConfig& config, size_t page_size) noexcept;

[[nodiscard]] constexpr size_t ebpf_cache_offset_table_offset(size_t response_size) noexcept {
    constexpr size_t alignment = alignof(uint16_t);
    return (sizeof(ebpf_cache_slot_header) + response_size + alignment - 1U) & ~(alignment - 1U);
}

[[nodiscard]] constexpr size_t ebpf_cache_active_slot_size(size_t response_size, size_t ttl_offset_count) noexcept {
    return ebpf_cache_offset_table_offset(response_size) + (ttl_offset_count * sizeof(uint16_t));
}

} // namespace shinku::backend::ebpf

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "config/config.h"
#include "ebpf_cache_abi.h"

#include <cstddef>
#include <cstdint>

namespace shinku::backend::ebpf {

/**
 * @brief Computed geometry of the BPF arena cache storage.
 *
 * Describes how the arena is carved into fixed-stride slots and how large the
 * arena must be to hold @ref entry_capacity entries. Both the host store and
 * the BPF program consume the same layout so their slot indexing agrees.
 */
struct EbpfCacheStorageLayout {
    uint32_t entry_capacity; ///< Maximum number of cache entries.
    uint32_t response_capacity; ///< Maximum response size in bytes per slot.
    uint32_t ttl_offset_capacity; ///< Maximum TTL offsets stored per slot.
    uint32_t slot_stride; ///< Bytes between consecutive slot starts.
    size_t required_arena_bytes; ///< Minimum arena size required for this layout.
    size_t arena_bytes; ///< Actual arena size in use (page-rounded).
    uint32_t arena_page_count; ///< Number of arena pages backing the storage.

    /// @return The layout expressed in the BPF-side @ref ebpf_cache_bpf_layout struct.
    [[nodiscard]] ebpf_cache_bpf_layout bpf_layout() const noexcept;

    bool operator==(const EbpfCacheStorageLayout&) const = default;
};

/**
 * @brief Compute the storage layout for a cache configuration and page size.
 * @param config The backend-neutral cache configuration.
 * @param page_size The arena page size in bytes.
 * @return The computed storage layout.
 */
[[nodiscard]] EbpfCacheStorageLayout
make_ebpf_cache_storage_layout(const config::CacheConfig& config, size_t page_size) noexcept;

/**
 * @brief Byte offset of the TTL offset table within a slot, for @p response_size.
 * @param response_size The per-slot response capacity in bytes.
 * @return The byte offset of the TTL offset table, aligned to @c alignof(uint16_t).
 */
[[nodiscard]] constexpr size_t ebpf_cache_offset_table_offset(size_t response_size) noexcept {
    constexpr size_t alignment = alignof(uint16_t);
    return (sizeof(ebpf_cache_slot_header) + response_size + alignment - 1U) & ~(alignment - 1U);
}

/**
 * @brief Total active size of a slot for the given response and TTL-offset counts.
 * @param response_size The per-slot response capacity in bytes.
 * @param ttl_offset_count The per-slot TTL-offset capacity.
 * @return The active slot size in bytes.
 */
[[nodiscard]] constexpr size_t ebpf_cache_active_slot_size(size_t response_size, size_t ttl_offset_count) noexcept {
    return ebpf_cache_offset_table_offset(response_size) + (ttl_offset_count * sizeof(uint16_t));
}

} // namespace shinku::backend::ebpf

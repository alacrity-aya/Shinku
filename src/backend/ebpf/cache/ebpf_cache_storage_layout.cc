// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_cache_storage_layout.h"

#include "config/config.h"
#include "ebpf_cache_abi.h"
#include <cstddef>
#include <cstdint>
#include <limits>

namespace shinku::backend::ebpf {
namespace {

constexpr uint32_t kDnsHeaderBytes = 12; ///< Fixed DNS message header size in bytes.
constexpr uint32_t kMinimumQuestionBytes = 5; ///< Smallest DNS question (name, QTYPE, QCLASS) in bytes.
constexpr uint32_t kMinimumResourceRecordBytes = 11; ///< Smallest resource record, bounding TTL-offset capacity.

/// Compile-time checks pinning the layout math to the BPF ABI limits.
static_assert(config::CacheConfig::kMaximumResponseBytes == SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES);
static_assert(SHINKU_EBPF_CACHE_SLOT_ALIGNMENT > 0);
static_assert((SHINKU_EBPF_CACHE_SLOT_ALIGNMENT & (SHINKU_EBPF_CACHE_SLOT_ALIGNMENT - 1U)) == 0);
static_assert(
    (config::CacheConfig::kMaximumResponseBytes - kDnsHeaderBytes - kMinimumQuestionBytes) / kMinimumResourceRecordBytes
    <= SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS
);
static_assert(SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE <= std::numeric_limits<uint32_t>::max());

} // namespace

/// Project this layout into the BPF-side geometry struct shared with the program.
ebpf_cache_bpf_layout EbpfCacheStorageLayout::bpf_layout() const noexcept {
    return {
        .entry_capacity = entry_capacity,
        .response_capacity = response_capacity,
        .ttl_offset_capacity = ttl_offset_capacity,
        .slot_stride = slot_stride,
    };
}

/// Compute TTL-offset capacity, slot stride, and page-rounded arena size for
/// the given cache configuration.
EbpfCacheStorageLayout
make_ebpf_cache_storage_layout(const config::CacheConfig& cache_config, size_t page_size) noexcept {
    // Maximum TTL offsets is the number of minimal resource records that fit in a response.
    const auto ttl_capacity =
        (cache_config.max_response_bytes() - kDnsHeaderBytes - kMinimumQuestionBytes) / kMinimumResourceRecordBytes;

    const auto active_capacity = ebpf_cache_active_slot_size(cache_config.max_response_bytes(), ttl_capacity);
    // Round the active slot size up to the arena slot alignment to form the stride.
    const size_t stride =
        (active_capacity + SHINKU_EBPF_CACHE_SLOT_ALIGNMENT - 1U) & ~(SHINKU_EBPF_CACHE_SLOT_ALIGNMENT - 1U);
    const size_t required_bytes = stride * cache_config.max_entries();
    // Round the required arena bytes up to a whole number of pages.
    const size_t page_count = (required_bytes / page_size) + ((required_bytes % page_size != 0U) ? 1U : 0U);

    return EbpfCacheStorageLayout {
        .entry_capacity = cache_config.max_entries(),
        .response_capacity = cache_config.max_response_bytes(),
        .ttl_offset_capacity = ttl_capacity,
        .slot_stride = static_cast<uint32_t>(stride),
        .required_arena_bytes = required_bytes,
        .arena_bytes = page_count * page_size,
        .arena_page_count = static_cast<uint32_t>(page_count),
    };
}

} // namespace shinku::backend::ebpf

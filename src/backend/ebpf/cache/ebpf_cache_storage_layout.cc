// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_cache_storage_layout.h"

#include "config/config.h"
#include "ebpf_cache_abi.h"
#include <cstddef>
#include <cstdint>
#include <limits>

namespace shinku::backend::ebpf {
namespace {

constexpr uint32_t kDnsHeaderBytes = 12;
constexpr uint32_t kMinimumQuestionBytes = 5;
constexpr uint32_t kMinimumResourceRecordBytes = 11;

static_assert(config::CacheConfig::kMaximumResponseBytes == SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES);
static_assert(SHINKU_EBPF_CACHE_SLOT_ALIGNMENT > 0);
static_assert((SHINKU_EBPF_CACHE_SLOT_ALIGNMENT & (SHINKU_EBPF_CACHE_SLOT_ALIGNMENT - 1U)) == 0);
static_assert(
    (config::CacheConfig::kMaximumResponseBytes - kDnsHeaderBytes - kMinimumQuestionBytes) / kMinimumResourceRecordBytes
    <= SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS
);
static_assert(SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE <= std::numeric_limits<uint32_t>::max());

} // namespace

ebpf_cache_bpf_layout EbpfCacheStorageLayout::bpf_layout() const noexcept {
    return {
        .entry_capacity = entry_capacity,
        .response_capacity = response_capacity,
        .ttl_offset_capacity = ttl_offset_capacity,
        .slot_stride = slot_stride,
    };
}

EbpfCacheStorageLayout
make_ebpf_cache_storage_layout(const config::CacheConfig& cache_config, size_t page_size) noexcept {
    const auto ttl_capacity =
        (cache_config.max_response_bytes() - kDnsHeaderBytes - kMinimumQuestionBytes) / kMinimumResourceRecordBytes;

    const auto active_capacity = ebpf_cache_active_slot_size(cache_config.max_response_bytes(), ttl_capacity);
    const size_t stride =
        (active_capacity + SHINKU_EBPF_CACHE_SLOT_ALIGNMENT - 1U) & ~(SHINKU_EBPF_CACHE_SLOT_ALIGNMENT - 1U);
    const size_t required_bytes = stride * cache_config.max_entries();
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

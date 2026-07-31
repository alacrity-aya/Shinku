// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/cache/ebpf_cache_map.h"
#include "backend/ebpf/cache/ebpf_cache_storage_layout.h"
#include "backend/ebpf/cache/ebpf_native_storage_binding.h"
#include "cache/cache_store.h"
#include "ebpf_cache_abi.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <system_error>
#include <vector>

namespace shinku::backend::ebpf {

class EbpfCacheStore final: public cache::CacheStore {
public:
    [[nodiscard]] static std::expected<std::unique_ptr<EbpfCacheStore>, std::error_code>
    create(EbpfCacheStorageLayout layout, EbpfNativeStorageBinding binding, ebpf_cache_secret secret) noexcept;

    [[nodiscard]] static std::expected<std::unique_ptr<EbpfCacheStore>, std::error_code> create_for_testing(
        EbpfCacheStorageLayout layout,
        EbpfNativeStorageBinding binding,
        ebpf_cache_secret secret,
        std::unique_ptr<EbpfCacheMap> map
    ) noexcept;

    ~EbpfCacheStore() override = default;

    [[nodiscard]] std::expected<cache::StoreOutcome, cache::CacheStoreError>
    store(const cache::CacheCandidate& candidate, cache::CacheTime now) noexcept override;

    [[nodiscard]] std::expected<cache::CleanupResult, cache::CacheStoreError> cleanup(cache::CacheTime now
    ) noexcept override;

private:
    static constexpr uint32_t kNoSlot = UINT32_MAX;
    static constexpr size_t kCleanupBatchSize = 256;

    struct SlotRecord {
        ebpf_cache_physical_key key {};
        uint64_t generation = 0;
        uint64_t expires_at_ns = 0;
        uint32_t next_free = kNoSlot;
    };

    EbpfCacheStore(
        EbpfCacheStorageLayout layout,
        EbpfNativeStorageBinding binding,
        ebpf_cache_secret secret,
        std::unique_ptr<EbpfCacheMap> map
    );

    [[nodiscard]] ebpf_cache_physical_key physical_key(const cache::CacheKey& key) const noexcept;
    [[nodiscard]] std::byte* slot(uint32_t slot_index) noexcept;
    [[nodiscard]] uint64_t next_generation() noexcept;
    [[nodiscard]] uint32_t allocate_slot() noexcept;
    void reclaim_slot(uint32_t slot_index) noexcept;
    void write_slot(
        uint32_t slot_index,
        const cache::CacheCandidate& candidate,
        uint64_t stored_at_ns,
        uint64_t expires_at_ns,
        uint64_t generation
    ) noexcept;
    void restore_slot_body(uint32_t slot_index, size_t body_size) noexcept;

    EbpfCacheStorageLayout layout_;
    EbpfNativeStorageBinding binding_;
    ebpf_cache_secret secret_;
    std::unique_ptr<EbpfCacheMap> map_;
    std::vector<SlotRecord> slots_;
    std::array<std::byte, SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE> rollback_scratch_ {};
    std::mutex mutex_;
    uint64_t next_generation_ = 1;
    uint32_t next_unused_slot_ = 0;
    uint32_t free_head_ = kNoSlot;
    uint32_t replacement_cursor_ = 0;
    uint32_t cleanup_cursor_ = 0;
    uint32_t cleanup_remaining_ = 0;
};

} // namespace shinku::backend::ebpf

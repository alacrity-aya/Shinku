// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_hash_table.h"
#include "cache/cache_candidate.h"
#include "cache/cache_store.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <system_error>
#include <vector>

namespace shinku::backend::dpdk {

class DpdkCacheStore final: public cache::CacheStore {
public:
    static constexpr uint32_t kNoSlot = UINT32_MAX;
    static constexpr size_t kPhysicalKeyBytes = 272;
    static constexpr size_t kResponseBytes = 512;
    static constexpr size_t kTtlOffsetCount = 45;

    struct Entry {
        std::array<std::byte, kPhysicalKeyBytes> physical_key {};
        cache::CacheEntryKind kind = cache::CacheEntryKind::Positive;
        cache::CacheTime stored_at;
        cache::CacheTime expires_at;
        std::array<std::byte, kResponseBytes> response {};
        std::array<uint16_t, kTtlOffsetCount> ttl_offsets {};
        uint16_t response_size = 0;
        uint16_t ttl_offset_count = 0;
        uint32_t next_free = kNoSlot;
        bool occupied = false;
    };

    [[nodiscard]] static std::expected<std::unique_ptr<DpdkCacheStore>, cache::CacheStoreError>
    create(uint32_t capacity, uint32_t maximum_response_bytes, int socket_id) noexcept;

    ~DpdkCacheStore() override;

    [[nodiscard]] std::expected<cache::StoreOutcome, cache::CacheStoreError>
    store(const cache::CacheCandidate& candidate, cache::CacheTime observed_at, cache::CacheTime now) noexcept override;

    [[nodiscard]] std::expected<cache::CleanupResult, cache::CacheStoreError> cleanup(cache::CacheTime now
    ) noexcept override;

    [[nodiscard]] const Entry* lookup(const cache::CacheKey& key, cache::CacheTime now) const noexcept;

private:
    static constexpr size_t kCleanupBatchSize = 32;

    using PhysicalKey = std::array<std::byte, kPhysicalKeyBytes>;
    using HashTable = DpdkHashTable<PhysicalKey, Entry>;

    DpdkCacheStore(
        uint32_t capacity,
        uint32_t maximum_response_bytes,
        std::vector<Entry> entries,
        HashTable hash
    ) noexcept;

    [[nodiscard]] static PhysicalKey physical_key(const cache::CacheKey& key) noexcept;
    [[nodiscard]] uint32_t allocate_entry() noexcept;
    void reclaim_entry(uint32_t index) noexcept;
    static void
    write_entry(Entry& entry, const cache::CacheCandidate& candidate, cache::CacheTime observed_at) noexcept;
    [[nodiscard]] std::expected<void, std::error_code> erase_entry(Entry& entry) noexcept;

    uint32_t capacity_;
    uint32_t maximum_response_bytes_;
    std::vector<Entry> entries_;
    HashTable hash_;
    mutable std::mutex mutex_;
    uint32_t next_unused_entry_ = 0;
    uint32_t free_head_ = kNoSlot;
    uint32_t replacement_cursor_ = 0;
    uint32_t cleanup_cursor_ = 0;
    uint32_t cleanup_remaining_ = 0;
};

} // namespace shinku::backend::dpdk

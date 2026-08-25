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

/**
 * @brief Cache store backed by a DPDK rte_hash plus a preallocated entry slab.
 *
 * Implements the @ref cache::CacheStore interface using a fixed-extent entry
 * vector and a DPDK hash table mapping physical keys (the wire form of @ref
 * cache::CacheKey) to entries. Entry allocation uses a free list plus a
 * replacement cursor, and cleanup sweeps are bounded per call so a single
 * sweep cannot monopolize a poll quantum.
 */
class DpdkCacheStore final: public cache::CacheStore {
public:
    static constexpr uint32_t kNoSlot = UINT32_MAX; ///< Sentinel meaning "no entry".
    static constexpr size_t kPhysicalKeyBytes = 272; ///< Size of a physical key in bytes.
    static constexpr size_t kResponseBytes = 512; ///< Backing storage per cached response.
    static constexpr size_t kTtlOffsetCount = 45; ///< Backing storage per entry for TTL offsets.

    /// A single cache entry, laid out for direct hashing by physical key.
    struct Entry {
        std::array<std::byte, kPhysicalKeyBytes> physical_key {}; ///< The physical (wire) key.
        cache::CacheEntryKind kind = cache::CacheEntryKind::Positive; ///< Positive or negative authority.
        cache::CacheTime stored_at; ///< When the entry was stored.
        cache::CacheTime expires_at; ///< When the entry expires.
        std::array<std::byte, kResponseBytes> response {}; ///< Cached DNS response payload.
        std::array<uint16_t, kTtlOffsetCount> ttl_offsets {}; ///< Byte offsets of each TTL in @ref response.
        uint16_t response_size = 0; ///< Number of valid bytes in @ref response.
        uint16_t ttl_offset_count = 0; ///< Number of valid entries in @ref ttl_offsets.
        uint32_t next_free = kNoSlot; ///< Next free entry index when this entry is on the free list.
        bool occupied = false; ///< True when this slot holds a live entry.
    };

    /**
     * @brief Construct a DPDK cache store.
     * @param capacity Maximum number of entries.
     * @param maximum_response_bytes Maximum response size the store will accept.
     * @param socket_id NUMA socket to allocate the hash table on.
     * @return The store, or a @ref cache::CacheStoreError on failure.
     */
    [[nodiscard]] static std::expected<std::unique_ptr<DpdkCacheStore>, cache::CacheStoreError>
    create(uint32_t capacity, uint32_t maximum_response_bytes, int socket_id) noexcept;

    ~DpdkCacheStore() override;

    [[nodiscard]] std::expected<cache::StoreOutcome, cache::CacheStoreError>
    store(const cache::CacheCandidate& candidate, cache::CacheTime observed_at, cache::CacheTime now) noexcept override;

    [[nodiscard]] std::expected<cache::CleanupResult, cache::CacheStoreError> cleanup(cache::CacheTime now
    ) noexcept override;

    /**
     * @brief Look up a live entry for @p key that has not expired by @p now.
     *
     * @note This read path is not part of the @ref cache::CacheStore interface;
     *       it is used by the DPDK packet path to answer queries from the cache.
     *
     * @return A pointer to the entry, or null if absent or expired.
     */
    [[nodiscard]] const Entry* lookup(const cache::CacheKey& key, cache::CacheTime now) const noexcept;

private:
    static constexpr size_t kCleanupBatchSize = 32; ///< Max entries examined per cleanup call.

    using PhysicalKey = std::array<std::byte, kPhysicalKeyBytes>;
    using HashTable = DpdkHashTable<PhysicalKey, Entry>;

    DpdkCacheStore(
        uint32_t capacity,
        uint32_t maximum_response_bytes,
        std::vector<Entry> entries,
        HashTable hash
    ) noexcept;

    /// @brief Materialize the physical (wire) key from a logical @ref cache::CacheKey.
    [[nodiscard]] static PhysicalKey physical_key(const cache::CacheKey& key) noexcept;
    /// @brief Allocate a free entry slot, evicting one if necessary.
    [[nodiscard]] uint32_t allocate_entry() noexcept;
    /// @brief Return an entry slot to the free list.
    void reclaim_entry(uint32_t index) noexcept;
    /// @brief Copy a candidate's payload into @p entry, stamping @p observed_at.
    static void
    write_entry(Entry& entry, const cache::CacheCandidate& candidate, cache::CacheTime observed_at) noexcept;
    /// @brief Remove an entry from the hash table and return its slot to the free list.
    [[nodiscard]] std::expected<void, std::error_code> erase_entry(Entry& entry) noexcept;

    uint32_t capacity_; ///< Maximum entry count.
    uint32_t maximum_response_bytes_; ///< Maximum accepted response size.
    std::vector<Entry> entries_; ///< Preallocated entry slab.
    HashTable hash_; ///< Physical-key to entry hash table.
    mutable std::mutex mutex_; ///< Guards the slab and free list against concurrent data-plane access.
    uint32_t next_unused_entry_ = 0; ///< High-water mark of the entry slab.
    uint32_t free_head_ = kNoSlot; ///< Head of the free list, or @ref kNoSlot if empty.
    uint32_t replacement_cursor_ = 0; ///< Cursor for victim selection when evicting.
    uint32_t cleanup_cursor_ = 0; ///< Cursor for bounded cleanup sweeps.
    uint32_t cleanup_remaining_ = 0; ///< Remaining expired entries to sweep this round.
};

} // namespace shinku::backend::dpdk

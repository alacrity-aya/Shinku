// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_hash_table.h"
#include "cache/cache_store.h"
#include "cache/cache_time.h"
#include "cache/dns/question.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <vector>

namespace shinku::backend::dpdk {

/// Physical key for correlating a DNS response to its pending query.
/// Composed of the 4-tuple plus the DNS transaction id, padded to 16 bytes.
struct DpdkPendingKey {
    uint32_t source_ipv4; ///< Source IPv4 address (network order).
    uint32_t destination_ipv4; ///< Destination IPv4 address (network order).
    uint16_t source_port; ///< Source UDP port (network order).
    uint16_t destination_port; ///< Destination UDP port (network order).
    uint16_t transaction_id; ///< DNS transaction id (network-order representation).
    uint16_t reserved = 0; ///< Padding to reach 16 bytes.
};
static_assert(sizeof(DpdkPendingKey) == 16);

/// Outcome of attempting to remember a pending query.
enum class DpdkPendingStoreResult : uint8_t {
    Inserted, ///< A new pending entry was inserted.
    Refreshed, ///< An existing pending entry's timestamp was refreshed.
    Skipped, ///< The entry was not recorded (e.g. capacity exhausted).
};

/**
 * @brief In-flight DNS query tracker for the DPDK cache path.
 *
 * Records queries awaiting responses so that an observed response can be
 * correlated back to the originating client and used to populate the cache.
 * Entries are stored in a preallocated slab indexed by a DPDK hash table and
 * reaped by a bounded cleanup sweep when they exceed the pending timeout.
 */
class DpdkPendingStore final {
public:
    static constexpr uint32_t kNoSlot = UINT32_MAX; ///< Sentinel meaning "no entry".

    /**
     * @brief Construct a pending store.
     * @param capacity Maximum number of pending entries.
     * @param socket_id NUMA socket to allocate the hash table on.
     * @return The store, or a std::error_code on failure.
     */
    [[nodiscard]] static std::expected<std::unique_ptr<DpdkPendingStore>, std::error_code>
    create(uint32_t capacity, int socket_id) noexcept;

    ~DpdkPendingStore();

    /**
     * @brief Record (or refresh) a pending query.
     * @param key Correlation key for the query.
     * @param question The decoded question triple.
     * @param now The current cache time.
     * @return Whether a new entry was inserted, an existing one refreshed, or skipped.
     */
    [[nodiscard]] DpdkPendingStoreResult
    remember(const DpdkPendingKey& key, const cache::dns::DnsQuestion& question, cache::CacheTime now) noexcept;

    /**
     * @brief Try to claim a pending entry for a matching response.
     *
     * A successful claim removes the entry so the response is processed exactly
     * once. A claim fails if no matching pending entry exists or if it has
     * already expired under @p timeout.
     *
     * @param key Correlation key for the query.
     * @param question The decoded question triple (must match the pending entry).
     * @param now The current cache time.
     * @param timeout Maximum age of a still-claimable pending entry.
     * @return True if the entry was claimed, or a std::error_code on failure.
     */
    [[nodiscard]] std::expected<bool, std::error_code> claim(
        const DpdkPendingKey& key,
        const cache::dns::DnsQuestion& question,
        cache::CacheTime now,
        std::chrono::nanoseconds timeout
    ) noexcept;

    /**
     * @brief Reap pending entries older than the configured timeout.
     * @param now The current cache time.
     * @param timeout Maximum age of a still-valid pending entry.
     * @return The cleanup result, or a std::error_code on failure.
     */
    [[nodiscard]] std::expected<cache::CleanupResult, std::error_code>
    cleanup(cache::CacheTime now, std::chrono::nanoseconds timeout) noexcept;

private:
    /// A single pending-query entry.
    struct Entry {
        DpdkPendingKey key {}; ///< Correlation key.
        cache::dns::DnsQuestion question {}; ///< The decoded question triple.
        cache::CacheTime last_seen; ///< When the query was last observed.
        uint32_t next_free = kNoSlot; ///< Next free entry index when on the free list.
        bool claimed = false; ///< True once a matching response has claimed this entry.
        bool occupied = false; ///< True when this slot holds a live entry.
    };
    using HashTable = DpdkHashTable<DpdkPendingKey, Entry>;

    DpdkPendingStore(uint32_t capacity, std::vector<Entry> entries, HashTable hash) noexcept;

    /// @brief Allocate a free entry slot, evicting one if necessary.
    [[nodiscard]] uint32_t allocate_entry() noexcept;
    /// @brief Return an entry slot to the free list.
    void reclaim_entry(uint32_t index) noexcept;

    uint32_t capacity_; ///< Maximum entry count.
    std::vector<Entry> entries_; ///< Preallocated entry slab.
    HashTable hash_; ///< Key to entry hash table.
    uint32_t next_unused_entry_ = 0; ///< High-water mark of the entry slab.
    uint32_t free_head_ = kNoSlot; ///< Head of the free list, or @ref kNoSlot if empty.
    uint32_t cleanup_cursor_ = 0; ///< Cursor for bounded cleanup sweeps.
    uint32_t cleanup_remaining_ = 0; ///< Remaining stale entries to sweep this round.
};

} // namespace shinku::backend::dpdk

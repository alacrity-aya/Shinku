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
#include <vector>

namespace shinku::backend::ebpf {

/**
 * @brief eBPF map-backed @ref cache::CacheStore sharing an arena with the BPF program.
 *
 * Stores cache entries in a BPF arena region laid out as a fixed-stride slot
 * array, indexed by a BPF hash map keyed on the physical (fingerprinted) key.
 * The host store mirrors slot bookkeeping (free list, replacement cursor,
 * bounded cleanup) so it can publish entries for the BPF hit path to serve.
 */
class EbpfCacheStore final: public cache::CacheStore {
public:
    /// @brief Construct the store for production, binding to a real BPF arena and map.
    [[nodiscard]] static std::unique_ptr<EbpfCacheStore>
    create(EbpfCacheStorageLayout layout, EbpfNativeStorageBinding binding, ebpf_cache_secret secret);

    /// @brief Construct the store with an injected map, for tests only.
    [[nodiscard]] static std::unique_ptr<EbpfCacheStore> create_for_testing(
        EbpfCacheStorageLayout layout,
        EbpfNativeStorageBinding binding,
        ebpf_cache_secret secret,
        std::unique_ptr<EbpfCacheMap> map
    );

    ~EbpfCacheStore() override = default;

    [[nodiscard]] std::expected<cache::StoreOutcome, cache::CacheStoreError>
    store(const cache::CacheCandidate& candidate, cache::CacheTime observed_at, cache::CacheTime now) noexcept override;

    [[nodiscard]] std::expected<cache::CleanupResult, cache::CacheStoreError>
    cleanup(cache::CacheTime now) noexcept override;

private:
    static constexpr uint32_t kNoSlot = UINT32_MAX; ///< Sentinel meaning "no slot".
    static constexpr size_t kCleanupBatchSize = 256; ///< Max slots examined per cleanup call.

    /// Host-side bookkeeping for a single arena slot.
    struct SlotRecord {
        ebpf_cache_physical_key key {}; ///< The physical key occupying this slot.
        uint64_t generation = 0; ///< Monotone generation to detect stale publications.
        uint64_t expires_at_ns = 0; ///< Expiry time in nanoseconds since boot.
        uint32_t next_free = kNoSlot; ///< Next free slot index when on the free list.
    };

    EbpfCacheStore(
        EbpfCacheStorageLayout layout,
        EbpfNativeStorageBinding binding,
        ebpf_cache_secret secret,
        std::unique_ptr<EbpfCacheMap> map
    );

    /// @brief Compute the physical (fingerprinted) key for a logical @ref cache::CacheKey.
    [[nodiscard]] ebpf_cache_physical_key physical_key(const cache::CacheKey& key) const noexcept;
    /// @return A pointer to the slot body at @p slot_index in the arena.
    [[nodiscard]] std::byte* slot(uint32_t slot_index) noexcept;
    /// @return The next publication generation number.
    [[nodiscard]] uint64_t next_generation() noexcept;
    /// @brief Allocate a free slot, evicting one if necessary.
    [[nodiscard]] uint32_t allocate_slot() noexcept;
    /// @brief Return a slot to the free list.
    void reclaim_slot(uint32_t slot_index) noexcept;
    /// @brief Publish a candidate's payload into a slot.
    void write_slot(
        uint32_t slot_index,
        const cache::CacheCandidate& candidate,
        uint64_t stored_at_ns,
        uint64_t expires_at_ns,
        uint64_t generation
    ) noexcept;
    /// @brief Restore a slot body from rollback scratch after a failed publication.
    void restore_slot_body(uint32_t slot_index, size_t body_size) noexcept;

    EbpfCacheStorageLayout layout_; ///< Slot/array geometry and arena sizing.
    EbpfNativeStorageBinding binding_; ///< Native arena/map bindings.
    ebpf_cache_secret secret_; ///< Secret used to fingerprint physical keys.
    std::unique_ptr<EbpfCacheMap> map_; ///< The BPF hash map (or test double).
    std::vector<SlotRecord> slots_; ///< Host-side slot bookkeeping.
    std::array<std::byte, SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE> rollback_scratch_ {}; ///< Scratch for rollback on failed publications.
    std::mutex mutex_; ///< Guards slot bookkeeping against concurrent data-plane access.
    uint64_t next_generation_ = 1; ///< Next generation number to stamp on a publication.
    uint32_t next_unused_slot_ = 0; ///< High-water mark of the slot array.
    uint32_t free_head_ = kNoSlot; ///< Head of the free list, or @ref kNoSlot if empty.
    uint32_t replacement_cursor_ = 0; ///< Cursor for victim selection when evicting.
    uint32_t cleanup_cursor_ = 0; ///< Cursor for bounded cleanup sweeps.
    uint32_t cleanup_remaining_ = 0; ///< Remaining expired slots to sweep this round.
};

} // namespace shinku::backend::ebpf

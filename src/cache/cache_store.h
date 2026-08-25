// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/cache_candidate.h"
#include "cache/cache_store_error.h"

#include <cstddef>
#include <cstdint>
#include <expected>

namespace shinku::cache {

/// Outcome of an attempted @ref CacheStore::store of a @ref CacheCandidate.
enum class StoreOutcome : uint8_t {
    Inserted, ///< A new entry was inserted into an empty slot.
    Updated, ///< An existing entry was refreshed in place.
    Replaced, ///< An existing entry was evicted and replaced.
    Rejected, ///< The candidate was refused (e.g. policy or capacity).
};

/// Result of a @ref CacheStore::cleanup sweep over expired entries.
struct CleanupResult {
    size_t removed_entries; ///< Number of entries removed during this sweep.
    bool more_work; ///< True if more expired entries remain for a follow-up sweep.
};

/**
 * @brief Backend-neutral interface for inserting and evicting cached responses.
 *
 * Concrete stores (eBPF map-backed, DPDK hash-table-backed) implement this
 * interface so the cache policy layer can store and clean entries without
 * depending on a specific data plane.
 */
class CacheStore {
public:
    CacheStore() = default;
    virtual ~CacheStore() = default;

    CacheStore(const CacheStore&) = delete;
    CacheStore& operator=(const CacheStore&) = delete;
    CacheStore(CacheStore&&) = delete;
    CacheStore& operator=(CacheStore&&) = delete;

    /**
     * @brief Store (or refresh) a parsed response in the cache.
     *
     * @param candidate The parsed response to store; its spans are borrowed
     *        and must be consumed synchronously during this call.
     * @param observed_at The timestamp at which the response was observed.
     * @param now The current cache time, used to compute expiry.
     * @return The store outcome, or a @ref CacheStoreError on failure.
     */
    [[nodiscard]] virtual std::expected<StoreOutcome, CacheStoreError>
    store(const CacheCandidate& candidate, CacheTime observed_at, CacheTime now) noexcept = 0;

    /**
     * @brief Remove expired entries from the cache.
     *
     * Implementations may bound the work performed per call; when @ref
     * CleanupResult::more_work is true the caller should sweep again.
     *
     * @param now The current cache time, used to identify expired entries.
     * @return The cleanup result, or a @ref CacheStoreError on failure.
     */
    [[nodiscard]] virtual std::expected<CleanupResult, CacheStoreError> cleanup(CacheTime now) noexcept = 0;
};

} // namespace shinku::cache

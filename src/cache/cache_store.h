// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/cache_candidate.h"
#include "cache/cache_store_error.h"

#include <cstddef>
#include <cstdint>
#include <expected>

namespace shinku::cache {

enum class StoreOutcome : uint8_t {
    Inserted,
    Updated,
    Replaced,
    Rejected,
};

struct CleanupResult {
    size_t removed_entries;
    bool more_work;
};

class CacheStore {
public:
    CacheStore() = default;
    virtual ~CacheStore() = default;

    CacheStore(const CacheStore&) = delete;
    CacheStore& operator=(const CacheStore&) = delete;
    CacheStore(CacheStore&&) = delete;
    CacheStore& operator=(CacheStore&&) = delete;

    [[nodiscard]] virtual std::expected<StoreOutcome, CacheStoreError>
    store(const CacheCandidate& candidate, CacheTime now) noexcept = 0;

    [[nodiscard]] virtual std::expected<CleanupResult, CacheStoreError> cleanup(CacheTime now) noexcept = 0;
};

} // namespace shinku::cache

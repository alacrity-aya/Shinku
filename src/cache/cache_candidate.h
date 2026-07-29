// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/cache_key.h"
#include "cache/cache_time.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace shinku::cache {

enum class CacheEntryKind : uint8_t {
    Positive,
    NxDomain,
    NoData,
};

struct CacheCandidate {
    CacheKey key;
    CacheEntryKind kind;
    CacheLifetime lifetime;
    // Both spans are borrowed and must be consumed synchronously. The response
    // expires when its packet callback returns; TTL offsets may expire on the
    // next classification by the producing DnsPolicy. Stores retain neither.
    std::span<const std::byte> response;
    std::span<const uint16_t> ttl_offsets;

    friend bool operator==(const CacheCandidate& lhs, const CacheCandidate& rhs) {
        return lhs.key == rhs.key && lhs.kind == rhs.kind && lhs.lifetime == rhs.lifetime
            && std::ranges::equal(lhs.response, rhs.response) && std::ranges::equal(lhs.ttl_offsets, rhs.ttl_offsets);
    }
};

} // namespace shinku::cache

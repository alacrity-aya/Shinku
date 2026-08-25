// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/cache_key.h"
#include "cache/cache_time.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace shinku::cache {

/// Classification of a cache entry's authority, which governs how its TTL is derived.
enum class CacheEntryKind : uint8_t {
    Positive, ///< A positive answer carrying resource records for the queried name.
    NxDomain, ///< A negative answer asserting the name does not exist (NXDOMAIN).
    NoData, ///< A negative answer asserting no data exists for the queried type (NOERROR, empty answer).
};

/**
 * @brief A parsed DNS response ready to insert into a @ref CacheStore.
 *
 * A CacheCandidate is the product of @ref cache::DnsPolicy::classify_response(); it
 * carries the cache key, the entry kind and lifetime, and borrowed views over
 * the response payload and the byte offsets of each TTL within it.
 *
 * @note Both @ref response and @ref ttl_offsets are borrowed and must be
 *       consumed synchronously. The response expires when its packet callback
 *       returns; TTL offsets may expire on the next classification by the
 *       producing @ref DnsPolicy. Stores retain neither.
 */
struct CacheCandidate {
    CacheKey key; ///< Cache lookup key derived from the question and namespace.
    CacheEntryKind kind; ///< Whether the entry is positive or negative (and which).
    CacheLifetime lifetime; ///< Number of seconds the entry may be served before expiry.
    std::span<const std::byte> response; ///< Borrowed view of the DNS response payload.
    std::span<const uint16_t> ttl_offsets; ///< Borrowed view of byte offsets to each TTL in @ref response.

    /// @brief Compares two candidates by all fields, including borrowed spans.
    friend bool operator==(const CacheCandidate& lhs, const CacheCandidate& rhs) {
        return lhs.key == rhs.key && lhs.kind == rhs.kind && lhs.lifetime == rhs.lifetime
            && std::ranges::equal(lhs.response, rhs.response) && std::ranges::equal(lhs.ttl_offsets, rhs.ttl_offsets);
    }
};

} // namespace shinku::cache

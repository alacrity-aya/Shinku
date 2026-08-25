// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/canonical_name.h"

#include <cstdint>

namespace shinku::cache {

/**
 * @brief Identifies the network namespace a cache entry belongs to.
 *
 * A cache entry is namespaced by the destination address and port of the
 * transport the query arrived on, so that identically-named queries on
 * distinct upstreams never collide in the cache.
 */
struct CacheNamespace {
    uint32_t destination_ipv4; ///< Destination IPv4 address in host byte order.
    uint16_t destination_port; ///< Destination port in host byte order.

    bool operator==(const CacheNamespace&) const = default;
};

/**
 * @brief Cache lookup key for a single DNS question.
 *
 * Combines the transport namespace with the canonical question triple so two
 * queries with the same @ref CacheNamespace and question resolve to the same
 * cache slot.
 */
struct CacheKey {
    CacheNamespace cache_namespace; ///< Transport namespace of the originating query.
    CanonicalDnsName question_name; ///< Canonical (lowercased) owner name of the question.
    uint16_t question_type; ///< DNS QTYPE of the question (e.g. A, AAAA).
    uint16_t question_class; ///< DNS QCLASS of the question (e.g. IN).

    bool operator==(const CacheKey&) const = default;
};

} // namespace shinku::cache

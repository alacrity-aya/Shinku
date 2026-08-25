// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/bypass_reason.h"
#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "cache/dns/wire_parser.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace shinku::cache {

/**
 * @brief Backend-neutral DNS cache policy: parse, judge, and produce candidates.
 *
 * A DnsPolicy owns the scratch buffer used while parsing a response and the
 * configuration that decides which responses are cacheable. It is not
 * thread-safe and is intended to be used by a single forwarding loop.
 */
class DnsPolicy {
public:
    /**
     * @brief Construct a policy.
     * @param max_response_bytes Maximum response size, in bytes, the policy will accept.
     * @param cache_negative Whether negative (NXDOMAIN/NOERROR-empty) responses may be cached.
     */
    DnsPolicy(uint32_t max_response_bytes, bool cache_negative) noexcept;

    DnsPolicy(const DnsPolicy&) = delete;
    DnsPolicy& operator=(const DnsPolicy&) = delete;
    DnsPolicy(DnsPolicy&&) = delete;
    DnsPolicy& operator=(DnsPolicy&&) = delete;

    /**
     * @brief Classify a complete DNS response and produce a cache candidate.
     *
     * The caller must supply a complete DNS payload from successful query
     * correlation. The result borrows @p message and this instance's scratch,
     * so it must be passed synchronously to @ref CacheStore::store() before
     * the callback returns and before calling classify_response() again on
     * this instance.
     *
     * @param message The complete DNS response payload.
     * @param cache_namespace The transport namespace of the originating query.
     * @return A cache candidate, or a @ref BypassReason explaining why the response was not cached.
     */
    [[nodiscard]] std::expected<CacheCandidate, BypassReason>
    classify_response(std::span<const std::byte> message, CacheNamespace cache_namespace) noexcept;

private:
    uint32_t max_response_bytes_; ///< Maximum accepted response size in bytes.
    bool cache_negative_; ///< Whether negative responses may be cached.
    std::array<uint16_t, dns::kMaxTtlOffsets> ttl_offsets_ {}; ///< Scratch for TTL offsets during classification.
};

} // namespace shinku::cache

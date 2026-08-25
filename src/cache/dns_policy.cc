// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/dns_policy.h"

#include "cache/bypass_reason.h"
#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "cache/dns/response_policy.h"
#include "cache/dns/wire_parser.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace shinku::cache {

/// Hold the response-size limit and negative-caching switch for classification.
DnsPolicy::DnsPolicy(uint32_t max_response_bytes, bool cache_negative) noexcept:
    max_response_bytes_(max_response_bytes),
    cache_negative_(cache_negative) {}

/**
 * @brief Classify a DNS response into a cacheable candidate or a bypass reason.
 *
 * Rejects messages that exceed the configured response-size limit or fail
 * wire parsing, then defers the policy judgment to @ref dns::judge_response
 * using the cached TTL-offset scratch space.
 */
std::expected<CacheCandidate, BypassReason>
DnsPolicy::classify_response(std::span<const std::byte> message, CacheNamespace cache_namespace) noexcept {
    if (message.size() > max_response_bytes_)
        return std::unexpected(BypassReason::ResponseTooLarge);

    auto parsed = dns::parse_response(message, ttl_offsets_);
    if (!parsed)
        return std::unexpected(BypassReason::MalformedResponse);

    return dns::judge_response(*parsed, cache_namespace, cache_negative_);
}

} // namespace shinku::cache

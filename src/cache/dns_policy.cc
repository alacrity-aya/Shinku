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

DnsPolicy::DnsPolicy(uint32_t max_response_bytes, bool cache_negative) noexcept:
    max_response_bytes_(max_response_bytes),
    cache_negative_(cache_negative) {}

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

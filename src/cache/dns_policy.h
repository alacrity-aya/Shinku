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

class DnsPolicy {
public:
    DnsPolicy(uint32_t max_response_bytes, bool cache_negative) noexcept;

    DnsPolicy(const DnsPolicy&) = delete;
    DnsPolicy& operator=(const DnsPolicy&) = delete;
    DnsPolicy(DnsPolicy&&) = delete;
    DnsPolicy& operator=(DnsPolicy&&) = delete;

    // The caller must supply a complete DNS payload from successful Query
    // Correlation. The result borrows message and this instance's scratch; pass
    // it synchronously to CacheStore::store() before the callback returns and
    // before calling classify_response() again on this instance.
    [[nodiscard]] std::expected<CacheCandidate, BypassReason>
    classify_response(std::span<const std::byte> message, CacheNamespace cache_namespace) noexcept;

private:
    uint32_t max_response_bytes_;
    bool cache_negative_;
    std::array<uint16_t, dns::kMaxTtlOffsets> ttl_offsets_ {};
};

} // namespace shinku::cache

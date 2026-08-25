// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/bypass_reason.h"
#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "cache/dns/parsed_response.h"

#include <expected>

namespace shinku::cache::dns {

/**
 * @brief Judge whether a parsed response is cacheable and build a candidate.
 *
 * Applies the backend-neutral cache policy (size limits, flag checks, TTL
 * selection, negative-cache rules) to a @ref ParsedResponse and either returns
 * a ready-to-store @ref CacheCandidate or a @ref BypassReason explaining why
 * the response was deliberately not cached.
 *
 * @param response The parsed response to judge.
 * @param cache_namespace The transport namespace of the originating query.
 * @param cache_negative Whether negative responses (NXDOMAIN/NOERROR-empty) may be cached.
 * @return A cache candidate, or a @ref BypassReason.
 */
[[nodiscard]] std::expected<CacheCandidate, BypassReason>
judge_response(const ParsedResponse& response, CacheNamespace cache_namespace, bool cache_negative) noexcept;

} // namespace shinku::cache::dns

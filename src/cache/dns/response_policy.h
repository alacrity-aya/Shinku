// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/bypass_reason.h"
#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "cache/dns/parsed_response.h"

#include <expected>

namespace shinku::cache::dns {

[[nodiscard]] std::expected<CacheCandidate, BypassReason>
judge_response(const ParsedResponse& response, CacheNamespace cache_namespace, bool cache_negative) noexcept;

} // namespace shinku::cache::dns

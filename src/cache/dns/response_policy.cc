// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/dns/response_policy.h"

#include "cache/bypass_reason.h"
#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "cache/dns/parsed_response.h"

#include <chrono>
#include <cstdint>
#include <expected>

namespace shinku::cache::dns {
namespace {

/// Response flag: a reply message (QR), not a query.
constexpr uint16_t kFlagQr = 0x8000U;
/// Mask isolating the opcode field within the flags word.
constexpr uint16_t kOpcodeMask = 0x7800U;
/// Response flag: the message was truncated (TC).
constexpr uint16_t kFlagTc = 0x0200U;
/// Query flag: recursion was desired (RD).
constexpr uint16_t kFlagRd = 0x0100U;
/// Response flag: the reserved Z bit, which must be clear.
constexpr uint16_t kFlagZ = 0x0040U;
/// Query flag: checking was disabled (CD).
constexpr uint16_t kFlagCd = 0x0010U;
/// Mask isolating the response-code field within the flags word.
constexpr uint16_t kRcodeMask = 0x000fU;
/// Response code 0: NOERROR.
constexpr uint16_t kRcodeNoError = 0;
/// Response code 3: NXDOMAIN, cached as a negative entry.
constexpr uint16_t kRcodeNxDomain = 3;
/// The only question type this cache serves: A.
constexpr uint16_t kTypeA = 1;
/// The only question class this cache serves: IN.
constexpr uint16_t kClassIn = 1;

} // namespace

/**
 * @brief Judge a parsed response against the cache policy.
 *
 * Validates the flags (a non-truncated reply with recursion desired, no
 * reserved or CD bits, opcode 0), the single question in IN/A, and the
 * response code (NOERROR or NXDOMAIN only). Negative kinds are accepted only
 * when negative caching is enabled and require a nonzero minimum TTL. The
 * returned candidate carries the response bytes and the TTL offsets to
 * rewrite on a hit.
 */
std::expected<CacheCandidate, BypassReason>
judge_response(const ParsedResponse& response, CacheNamespace cache_namespace, bool cache_negative) noexcept {
    if ((response.flags & kFlagQr) == 0)
        return std::unexpected(BypassReason::NotAResponse);
    if ((response.flags & kOpcodeMask) != 0)
        return std::unexpected(BypassReason::UnsupportedOpcode);
    if (response.question_count != 1)
        return std::unexpected(BypassReason::QuestionCountMismatch);
    if ((response.flags & kFlagTc) != 0)
        return std::unexpected(BypassReason::TruncatedResponse);
    if (response.additional_count != 0)
        return std::unexpected(BypassReason::AdditionalSectionPresent);
    if ((response.flags & kFlagRd) == 0)
        return std::unexpected(BypassReason::RecursionNotDesired);
    if ((response.flags & kFlagCd) != 0)
        return std::unexpected(BypassReason::CheckingDisabled);
    if ((response.flags & kFlagZ) != 0)
        return std::unexpected(BypassReason::ReservedFlagSet);
    if (!response.question_name)
        return std::unexpected(BypassReason::UnsupportedQuestionEncoding);
    if (response.question_type != kTypeA)
        return std::unexpected(BypassReason::UnsupportedQuestionType);
    if (response.question_class != kClassIn)
        return std::unexpected(BypassReason::UnsupportedQuestionClass);

    const auto rcode = static_cast<uint16_t>(response.flags & kRcodeMask);
    if (rcode != kRcodeNoError && rcode != kRcodeNxDomain)
        return std::unexpected(BypassReason::UnsupportedRcode);

    CacheEntryKind kind = CacheEntryKind::Positive;
    if (rcode == kRcodeNxDomain)
        kind = CacheEntryKind::NxDomain;
    else if (response.authority_has_in_soa)
        kind = CacheEntryKind::NoData;

    if (kind != CacheEntryKind::Positive && !cache_negative)
        return std::unexpected(BypassReason::NegativeCachingDisabled);
    if (!response.minimum_ttl)
        return std::unexpected(BypassReason::NoResourceRecordTtl);
    if (*response.minimum_ttl == 0)
        return std::unexpected(BypassReason::ZeroLifetime);

    return CacheCandidate {
        .key =
            CacheKey {
                .cache_namespace = cache_namespace,
                .question_name = *response.question_name,
                .question_type = response.question_type,
                .question_class = response.question_class,
            },
        .kind = kind,
        .lifetime = std::chrono::seconds { *response.minimum_ttl },
        .response = response.message,
        .ttl_offsets = response.ttl_offsets,
    };
}

} // namespace shinku::cache::dns

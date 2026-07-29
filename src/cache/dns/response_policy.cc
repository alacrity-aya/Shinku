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

constexpr uint16_t kFlagQr = 0x8000U;
constexpr uint16_t kOpcodeMask = 0x7800U;
constexpr uint16_t kFlagTc = 0x0200U;
constexpr uint16_t kFlagRd = 0x0100U;
constexpr uint16_t kFlagZ = 0x0040U;
constexpr uint16_t kFlagCd = 0x0010U;
constexpr uint16_t kRcodeMask = 0x000fU;
constexpr uint16_t kRcodeNoError = 0;
constexpr uint16_t kRcodeNxDomain = 3;
constexpr uint16_t kTypeA = 1;
constexpr uint16_t kClassIn = 1;

} // namespace

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
    if (response.question_is_compressed || !response.question_name)
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

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <string_view>

namespace shinku::cache {

enum class BypassReason : uint8_t {
    ResponseTooLarge,
    MalformedResponse,
    NotAResponse,
    UnsupportedOpcode,
    QuestionCountMismatch,
    TruncatedResponse,
    AdditionalSectionPresent,
    RecursionNotDesired,
    CheckingDisabled,
    ReservedFlagSet,
    UnsupportedQuestionEncoding,
    UnsupportedQuestionType,
    UnsupportedQuestionClass,
    UnsupportedRcode,
    NegativeCachingDisabled,
    NoResourceRecordTtl,
    ZeroLifetime,
};

[[nodiscard]] constexpr std::string_view bypass_reason_name(BypassReason reason) noexcept {
    switch (reason) {
        case BypassReason::ResponseTooLarge:
            return "response too large";
        case BypassReason::MalformedResponse:
            return "malformed response";
        case BypassReason::NotAResponse:
            return "not a response";
        case BypassReason::UnsupportedOpcode:
            return "unsupported opcode";
        case BypassReason::QuestionCountMismatch:
            return "question count mismatch";
        case BypassReason::TruncatedResponse:
            return "truncated response";
        case BypassReason::AdditionalSectionPresent:
            return "additional section present";
        case BypassReason::RecursionNotDesired:
            return "recursion not desired";
        case BypassReason::CheckingDisabled:
            return "checking disabled";
        case BypassReason::ReservedFlagSet:
            return "reserved flag set";
        case BypassReason::UnsupportedQuestionEncoding:
            return "unsupported question encoding";
        case BypassReason::UnsupportedQuestionType:
            return "unsupported question type";
        case BypassReason::UnsupportedQuestionClass:
            return "unsupported question class";
        case BypassReason::UnsupportedRcode:
            return "unsupported rcode";
        case BypassReason::NegativeCachingDisabled:
            return "negative caching disabled";
        case BypassReason::NoResourceRecordTtl:
            return "no resource record ttl";
        case BypassReason::ZeroLifetime:
            return "zero lifetime";
    }
    return "unknown";
}

} // namespace shinku::cache

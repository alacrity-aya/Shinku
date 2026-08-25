// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <string_view>
#include <utility>

namespace shinku::cache {

/// Reason a parsed DNS response was deliberately not cached by the policy layer.
enum class BypassReason : uint8_t {
    ResponseTooLarge, ///< The response exceeded the configured size limit.
    MalformedResponse, ///< The response failed to parse.
    NotAResponse, ///< The message was not a response (QR bit clear).
    UnsupportedOpcode, ///< The OPCODE is not a standard query.
    QuestionCountMismatch, ///< The question count was not exactly one.
    TruncatedResponse, ///< The TC bit was set, indicating a truncated response.
    AdditionalSectionPresent, ///< An additional section was present and unsupported.
    RecursionNotDesired, ///< The RD bit was not set by the client.
    CheckingDisabled, ///< The CD bit was set, disabling DNSSEC validation.
    ReservedFlagSet, ///< A reserved header flag was set.
    UnsupportedQuestionEncoding, ///< The question name used an unsupported encoding.
    UnsupportedQuestionType, ///< The QTYPE is not cacheable.
    UnsupportedQuestionClass, ///< The QCLASS is not cacheable.
    UnsupportedRcode, ///< The RCODE is not cacheable.
    NegativeCachingDisabled, ///< The response is negative but negative caching is off.
    NoResourceRecordTtl, ///< No resource record contributed a TTL.
    ZeroLifetime, ///< The computed cache lifetime was zero or negative.
};

/**
 * @brief Return a lowercase human-readable name for a @ref BypassReason.
 *
 * Used in operator-facing diagnostics and logs to explain why a response was
 * not cached.
 *
 * @param reason The bypass reason to name.
 * @return A stable string view naming the reason.
 */
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
    std::unreachable();
}

} // namespace shinku::cache

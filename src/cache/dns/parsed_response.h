// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/canonical_name.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace shinku::cache::dns {

struct ParsedResponse {
    std::span<const std::byte> message;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
    std::optional<CanonicalDnsName> question_name;
    uint16_t question_type;
    uint16_t question_class;
    bool question_is_compressed;
    std::optional<uint32_t> minimum_ttl;
    bool authority_has_in_soa;
    std::span<const uint16_t> ttl_offsets;

    friend bool operator==(const ParsedResponse& lhs, const ParsedResponse& rhs) {
        return std::ranges::equal(lhs.message, rhs.message) && lhs.flags == rhs.flags
            && lhs.question_count == rhs.question_count && lhs.answer_count == rhs.answer_count
            && lhs.authority_count == rhs.authority_count && lhs.additional_count == rhs.additional_count
            && lhs.question_name == rhs.question_name && lhs.question_type == rhs.question_type
            && lhs.question_class == rhs.question_class && lhs.question_is_compressed == rhs.question_is_compressed
            && lhs.minimum_ttl == rhs.minimum_ttl && lhs.authority_has_in_soa == rhs.authority_has_in_soa
            && std::ranges::equal(lhs.ttl_offsets, rhs.ttl_offsets);
    }
};

} // namespace shinku::cache::dns

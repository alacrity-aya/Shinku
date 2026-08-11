// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/canonical_name.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <tuple>

namespace shinku::cache::dns {

struct ParsedResponse {
    std::span<const std::byte> message;
    uint16_t flags;
    uint16_t question_count;
    uint16_t additional_count;
    std::optional<CanonicalDnsName> question_name;
    uint16_t question_type;
    uint16_t question_class;
    std::optional<uint32_t> minimum_ttl;
    bool authority_has_in_soa;
    std::span<const uint16_t> ttl_offsets;

    [[nodiscard]] auto members() const {
        return std::tie(
            flags,
            question_count,
            additional_count,
            question_name,
            question_type,
            question_class,
            minimum_ttl,
            authority_has_in_soa
        );
    }

    friend bool operator==(const ParsedResponse& lhs, const ParsedResponse& rhs) {
        return std::ranges::equal(lhs.message, rhs.message) && lhs.members() == rhs.members()
            && std::ranges::equal(lhs.ttl_offsets, rhs.ttl_offsets);
    }
};

} // namespace shinku::cache::dns

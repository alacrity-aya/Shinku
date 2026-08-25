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

/**
 * @brief A decoded DNS response message, with pointers into the original bytes.
 *
 * @ref ParsedResponse is the product of @ref parse_response. It exposes the
 * header flags, the question triple, the minimum TTL across resource records,
 * and the byte offsets of each TTL so the caller can later patch TTLs in place.
 *
 * @note The @ref message and @ref ttl_offsets spans borrow the caller's
 *       buffer; the @ref ParsedResponse is only valid while those buffers live.
 */
struct ParsedResponse {
    std::span<const std::byte> message; ///< The original DNS message bytes.
    uint16_t flags; ///< The DNS header flags word (QR/AA/TC/RD/RA/RCODE, etc.).
    uint16_t question_count; ///< Number of entries in the question section.
    uint16_t additional_count; ///< Number of entries in the additional section.
    std::optional<CanonicalDnsName> question_name; ///< Canonical owner name of the question, if present.
    uint16_t question_type; ///< DNS QTYPE of the question.
    uint16_t question_class; ///< DNS QCLASS of the question.
    std::optional<uint32_t> minimum_ttl; ///< Smallest TTL across the answer/authority sections.
    bool authority_has_in_soa; ///< True if the authority section contains a SOA record.
    std::span<const uint16_t> ttl_offsets; ///< Byte offsets of each TTL field within @ref message.

    /// @return A tuple of the scalar members used by @ref operator==.
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

    /// @brief Compares two responses by message bytes, scalar members, and TTL offsets.
    friend bool operator==(const ParsedResponse& lhs, const ParsedResponse& rhs) {
        return std::ranges::equal(lhs.message, rhs.message) && lhs.members() == rhs.members()
            && std::ranges::equal(lhs.ttl_offsets, rhs.ttl_offsets);
    }
};

} // namespace shinku::cache::dns

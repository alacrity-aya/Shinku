// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/dns/parse_error.h"
#include "cache/dns/parsed_response.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace shinku::cache::dns {

/// Maximum number of bytes accepted in a single DNS message (RFC 1035 §4.1).
inline constexpr size_t kMaxDnsMessageBytes = 512;
/// Upper bound on the number of TTL offsets recorded per response; bounds scratch usage.
inline constexpr size_t kMaxTtlOffsets = 45;

/**
 * @brief Parse a DNS message into a @ref ParsedResponse.
 *
 * Walks the message header, the question section, and the answer/authority
 * sections to collect the response flags, question triple, the minimum TTL
 * observed across resource records, and the byte offsets of each TTL field.
 *
 * The TTL offsets are written into @p ttl_offset_scratch so the caller can
 * later patch TTLs in place on a cached response without re-parsing it.
 *
 * @param message Raw bytes of the DNS message, at most @ref kMaxDnsMessageBytes.
 * @param ttl_offset_scratch Caller-owned scratch buffer that receives TTL byte
 *        offsets; the returned @ref ParsedResponse::ttl_offsets views into it.
 * @return The parsed response, or a @ref ParseError describing the first defect.
 */
[[nodiscard]] std::expected<ParsedResponse, ParseError>
parse_response(std::span<const std::byte> message, std::span<uint16_t, kMaxTtlOffsets> ttl_offset_scratch) noexcept;

} // namespace shinku::cache::dns

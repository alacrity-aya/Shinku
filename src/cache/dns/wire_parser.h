// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/dns/parse_error.h"
#include "cache/dns/parsed_response.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace shinku::cache::dns {

inline constexpr size_t kMaxDnsMessageBytes = 512;
inline constexpr size_t kMaxTtlOffsets = 45;

[[nodiscard]] std::expected<ParsedResponse, ParseError>
parse_response(std::span<const std::byte> message, std::span<uint16_t> ttl_offset_scratch) noexcept;

} // namespace shinku::cache::dns

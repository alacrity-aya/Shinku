// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/dns/wire_parser.h"

#include "cache/canonical_name.h"
#include "cache/dns/parse_error.h"
#include "cache/dns/parsed_response.h"
#include "cache/dns/wire_io.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace shinku::cache::dns {
namespace {

constexpr size_t kDnsHeaderSize = 12;
constexpr size_t kQuestionFieldsSize = 4;
constexpr size_t kResourceRecordFieldsSize = 10;
constexpr size_t kMinimumResourceRecordSize = 1 + kResourceRecordFieldsSize;
constexpr uint16_t kTypeOpt = 41;
constexpr uint16_t kTypeSoa = 6;
constexpr uint16_t kClassIn = 1;
constexpr uint32_t kTtlHighBit = 0x8000'0000U;

static_assert((kMaxDnsMessageBytes - kDnsHeaderSize) / kMinimumResourceRecordSize <= kMaxTtlOffsets);

enum class DnsSection : uint8_t {
    Answer,
    Authority,
    Additional,
};

struct EncodedName {
    size_t end_offset;
    bool compressed;
};

std::expected<EncodedName, ParseError> scan_encoded_name(std::span<const std::byte> message, size_t start) noexcept {
    size_t cursor = start;
    while (cursor < message.size()) {
        const auto first = std::to_integer<uint8_t>(message[cursor]);
        const auto label_type = static_cast<uint8_t>(first & 0xc0U);

        if (label_type == 0xc0U) {
            if (message.size() - cursor < 2)
                return std::unexpected(ParseError::NameTruncated);
            cursor += 2;
            if (cursor - start > CanonicalDnsName::kMaxWireSize)
                return std::unexpected(ParseError::NameTooLong);
            return EncodedName { .end_offset = cursor, .compressed = true };
        }
        if (label_type != 0)
            return std::unexpected(ParseError::InvalidLabelType);

        ++cursor;
        if (first == 0) {
            if (cursor - start > CanonicalDnsName::kMaxWireSize)
                return std::unexpected(ParseError::NameTooLong);
            return EncodedName { .end_offset = cursor, .compressed = false };
        }
        if (message.size() - cursor < first)
            return std::unexpected(ParseError::NameTruncated);

        cursor += first;
        if (cursor - start >= CanonicalDnsName::kMaxWireSize)
            return std::unexpected(ParseError::NameTooLong);
    }

    return std::unexpected(ParseError::NameTruncated);
}

} // namespace

std::expected<ParsedResponse, ParseError>
parse_response(std::span<const std::byte> message, std::span<uint16_t, kMaxTtlOffsets> ttl_offset_scratch) noexcept {
    if (message.size() > kMaxDnsMessageBytes)
        return std::unexpected(ParseError::MessageTooLarge);
    if (message.size() < kDnsHeaderSize)
        return std::unexpected(ParseError::HeaderTruncated);

    const uint16_t flags = wire::read_u16(message, 2);
    const uint16_t question_count = wire::read_u16(message, 4);
    const uint16_t answer_count = wire::read_u16(message, 6);
    const uint16_t authority_count = wire::read_u16(message, 8);
    const uint16_t additional_count = wire::read_u16(message, 10);

    size_t cursor = kDnsHeaderSize;
    std::optional<CanonicalDnsName> question_name;
    uint16_t question_type = 0;
    uint16_t question_class = 0;

    for (uint16_t index = 0; index < question_count; ++index) {
        const size_t name_start = cursor;
        auto encoded_name = scan_encoded_name(message, cursor);
        if (!encoded_name)
            return std::unexpected(encoded_name.error());
        cursor = encoded_name->end_offset;

        if (message.size() - cursor < kQuestionFieldsSize)
            return std::unexpected(ParseError::QuestionFieldsTruncated);

        if (index == 0) {
            question_type = wire::read_u16(message, cursor);
            question_class = wire::read_u16(message, cursor + 2);
            if (!encoded_name->compressed) {
                auto canonical = CanonicalDnsName::from_wire(message.subspan(name_start, cursor - name_start));
                assert(canonical.has_value());
                question_name = *canonical;
            }
        }
        cursor += kQuestionFieldsSize;
    }

    size_t ttl_offset_count = 0;
    std::optional<uint32_t> minimum_ttl;
    bool authority_has_in_soa = false;

    const auto scan_records = [&](uint16_t count, DnsSection section) -> std::expected<void, ParseError> {
        for (uint16_t index = 0; index < count; ++index) {
            auto owner = scan_encoded_name(message, cursor);
            if (!owner)
                return std::unexpected(owner.error());
            cursor = owner->end_offset;

            if (message.size() - cursor < kResourceRecordFieldsSize)
                return std::unexpected(ParseError::ResourceRecordHeaderTruncated);

            const uint16_t type = wire::read_u16(message, cursor);
            const uint16_t rr_class = wire::read_u16(message, cursor + 2);
            const size_t ttl_offset = cursor + 4;
            const uint32_t wire_ttl = wire::read_u32(message, ttl_offset);
            const uint16_t rdata_size = wire::read_u16(message, cursor + 8);
            cursor += kResourceRecordFieldsSize;

            if (message.size() - cursor < rdata_size)
                return std::unexpected(ParseError::ResourceDataTruncated);

            if (type != kTypeOpt) {
                ttl_offset_scratch[ttl_offset_count++] = static_cast<uint16_t>(ttl_offset);
                const uint32_t ttl = (wire_ttl & kTtlHighBit) == 0 ? wire_ttl : 0;
                minimum_ttl = minimum_ttl ? std::min(*minimum_ttl, ttl) : ttl;
            }

            if (section == DnsSection::Authority && type == kTypeSoa && rr_class == kClassIn)
                authority_has_in_soa = true;

            cursor += rdata_size;
        }
        return {};
    };

    if (auto result = scan_records(answer_count, DnsSection::Answer); !result)
        return std::unexpected(result.error());
    if (auto result = scan_records(authority_count, DnsSection::Authority); !result)
        return std::unexpected(result.error());
    if (auto result = scan_records(additional_count, DnsSection::Additional); !result)
        return std::unexpected(result.error());

    return ParsedResponse {
        .message = message,
        .flags = flags,
        .question_count = question_count,
        .additional_count = additional_count,
        .question_name = question_name,
        .question_type = question_type,
        .question_class = question_class,
        .minimum_ttl = minimum_ttl,
        .authority_has_in_soa = authority_has_in_soa,
        .ttl_offsets = ttl_offset_scratch.first(ttl_offset_count),
    };
}

} // namespace shinku::cache::dns

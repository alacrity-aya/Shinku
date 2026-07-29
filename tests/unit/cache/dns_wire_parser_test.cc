// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/dns/wire_parser.h"

#include "cache/dns/parse_error.h"
#include "dns_test_message.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

using shinku::cache::dns::kMaxTtlOffsets;
using shinku::cache::dns::parse_response;
using shinku::cache::dns::ParseError;
using namespace shinku::cache::test;

std::array<uint16_t, kMaxTtlOffsets> scratch {};

} // namespace

TEST_CASE("wire parser extracts question and complete TTL plan") {
    auto message = recursive_response(1, 1);
    const auto owner = pointer_owner();
    const auto address = ipv4_rdata();
    append_record(message, owner, 1, 1, 300, address);
    append_record(message, owner, 6, 1, 60, {});
    message.push_back(std::byte { 0xde });
    message.push_back(std::byte { 0xad });

    auto parsed = parse_response(message, scratch);

    REQUIRE(parsed.has_value());
    REQUIRE(parsed->question_name.has_value());
    CHECK(std::ranges::equal(parsed->question_name->wire(), wire_name("www.example")));
    CHECK(parsed->question_type == 1);
    CHECK(parsed->question_class == 1);
    CHECK_FALSE(parsed->question_is_compressed);
    CHECK(parsed->minimum_ttl == 60);
    CHECK(parsed->authority_has_in_soa);
    REQUIRE(parsed->ttl_offsets.size() == 2);
    CHECK(parsed->ttl_offsets[0] == 35);
    CHECK(parsed->ttl_offsets[1] == 51);
    CHECK(parsed->message.size() == message.size());
}

TEST_CASE("ParsedResponse equality compares owned facts and borrowed contents") {
    auto first_message = recursive_response(1);
    const auto owner = pointer_owner();
    const auto address = ipv4_rdata();
    append_record(first_message, owner, 1, 1, 30, address);
    auto second_message = first_message;
    std::array<uint16_t, kMaxTtlOffsets> first_scratch {};
    std::array<uint16_t, kMaxTtlOffsets> second_scratch {};

    auto first = parse_response(first_message, first_scratch);
    auto second = parse_response(second_message, second_scratch);
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    CHECK(*first == *second);

    auto other_name = shinku::cache::CanonicalDnsName::from_wire(wire_name("api.example"));
    REQUIRE(other_name.has_value());
    second->question_name = *other_name;
    CHECK(*first != *second);
    second->question_name = first->question_name;
    second_message.back() = std::byte { 2 };
    CHECK(*first != *second);
    second_message.back() = first_message.back();
    second_scratch.front() += 1;
    CHECK(*first != *second);
}

TEST_CASE("wire parser treats RR compression pointers as opaque encoded terminators") {
    auto message = recursive_response(1);
    const auto out_of_range_owner = pointer_owner(0xff);
    const auto address = ipv4_rdata();
    append_record(message, out_of_range_owner, 1, 1, 30, address);

    auto parsed = parse_response(message, scratch);

    REQUIRE(parsed.has_value());
    CHECK(parsed->minimum_ttl == 30);
    REQUIRE(parsed->ttl_offsets.size() == 1);
}

TEST_CASE("wire parser reports a compressed Question without resolving it") {
    auto message = header(0x8180, 1, 0, 0, 0);
    const auto compressed = pointer_owner();
    append_question(message, compressed, 1, 1);

    auto parsed = parse_response(message, scratch);

    REQUIRE(parsed.has_value());
    CHECK(parsed->question_is_compressed);
    CHECK_FALSE(parsed->question_name.has_value());
}

TEST_CASE("wire parser interprets a TTL high bit as zero") {
    auto message = recursive_response(1);
    const auto owner = pointer_owner();
    const auto address = ipv4_rdata();
    append_record(message, owner, 1, 1, 0x8000'0001U, address);

    auto parsed = parse_response(message, scratch);

    REQUIRE(parsed.has_value());
    CHECK(parsed->minimum_ttl == 0);
}

TEST_CASE("wire parser excludes OPT pseudo-record TTL fields") {
    auto message = recursive_response(0, 0, 1);
    const auto root = wire_name(".");
    append_record(message, root, 41, 1232, 0x0000'8000U, {});

    auto parsed = parse_response(message, scratch);

    REQUIRE(parsed.has_value());
    CHECK_FALSE(parsed->minimum_ttl.has_value());
    CHECK(parsed->ttl_offsets.empty());
}

TEST_CASE("wire parser fills the complete 512-byte TTL offset bound") {
    auto message = header(0x8180, 0, static_cast<uint16_t>(kMaxTtlOffsets), 0, 0);
    const auto root = wire_name(".");
    for (size_t index = 0; index < kMaxTtlOffsets; ++index)
        append_record(message, root, 1, 1, static_cast<uint32_t>(index + 1), {});
    REQUIRE(message.size() == 507);

    auto parsed = parse_response(message, scratch);

    REQUIRE(parsed.has_value());
    CHECK(parsed->ttl_offsets.size() == kMaxTtlOffsets);
    CHECK(parsed->minimum_ttl == 1);

    std::array<uint16_t, kMaxTtlOffsets - 1> undersized_scratch {};
    auto without_capacity = parse_response(message, undersized_scratch);
    REQUIRE_FALSE(without_capacity.has_value());
    CHECK(without_capacity.error() == ParseError::TtlOffsetCapacityExceeded);
}

TEST_CASE("wire parser rejects malformed message boundaries") {
    SECTION("header") {
        std::vector<std::byte> message(11);
        auto parsed = parse_response(message, scratch);
        REQUIRE_FALSE(parsed.has_value());
        CHECK(parsed.error() == ParseError::HeaderTruncated);
    }

    SECTION("reserved label type") {
        auto message = header(0x8180, 1, 0, 0, 0);
        message.push_back(std::byte { 0x40 });
        auto parsed = parse_response(message, scratch);
        REQUIRE_FALSE(parsed.has_value());
        CHECK(parsed.error() == ParseError::InvalidLabelType);
    }

    SECTION("question fields") {
        auto message = header(0x8180, 1, 0, 0, 0);
        const auto question_name = wire_name("www.example");
        append_bytes(message, question_name);
        append_u16(message, 1);
        auto parsed = parse_response(message, scratch);
        REQUIRE_FALSE(parsed.has_value());
        CHECK(parsed.error() == ParseError::QuestionFieldsTruncated);
    }

    SECTION("RR header") {
        auto message = recursive_response(1);
        const auto owner = pointer_owner();
        append_bytes(message, owner);
        append_u16(message, 1);
        auto parsed = parse_response(message, scratch);
        REQUIRE_FALSE(parsed.has_value());
        CHECK(parsed.error() == ParseError::ResourceRecordHeaderTruncated);
    }

    SECTION("RDATA") {
        auto message = recursive_response(1);
        const auto owner = pointer_owner();
        append_bytes(message, owner);
        append_u16(message, 1);
        append_u16(message, 1);
        append_u32(message, 30);
        append_u16(message, 4);
        message.push_back(std::byte { 192 });
        auto parsed = parse_response(message, scratch);
        REQUIRE_FALSE(parsed.has_value());
        CHECK(parsed.error() == ParseError::ResourceDataTruncated);
    }
}

TEST_CASE("wire parser rejects input beyond the ring-event DNS capacity") {
    std::vector<std::byte> message(513);
    auto parsed = parse_response(message, scratch);
    REQUIRE_FALSE(parsed.has_value());
    CHECK(parsed.error() == ParseError::MessageTooLarge);
}

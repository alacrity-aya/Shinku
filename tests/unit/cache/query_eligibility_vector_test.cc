// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include <catch2/catch_test_macros.hpp>

#define TOML_EXCEPTIONS 0
#include <toml++/toml.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

uint8_t hex_nibble(char value) {
    if (value >= '0' && value <= '9')
        return static_cast<uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f')
        return static_cast<uint8_t>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F')
        return static_cast<uint8_t>(value - 'A' + 10);
    return 0xff;
}

std::expected<std::vector<std::byte>, std::string> decode_hex(std::string_view text) {
    if (text.size() % 2 != 0)
        return std::unexpected("hex string has odd length");

    std::vector<std::byte> result;
    result.reserve(text.size() / 2);
    for (size_t offset = 0; offset < text.size(); offset += 2) {
        const uint8_t high = hex_nibble(text[offset]);
        const uint8_t low = hex_nibble(text[offset + 1]);
        if (high == 0xff || low == 0xff)
            return std::unexpected("hex string contains a non-hex character");
        result.push_back(static_cast<std::byte>((high << 4U) | low));
    }
    return result;
}

} // namespace

TEST_CASE("Query Eligibility vectors have a backend-neutral schema") {
    const std::set<std::string> expected_conditions {
        "ad",
        "ancount",
        "baseline",
        "cd",
        "compressed_qname",
        "dnssec_do",
        "ecs",
        "edns",
        "nscount",
        "opcode",
        "qclass",
        "qdcount_multiple",
        "qdcount_zero",
        "qname_truncated",
        "qr",
        "qtype",
        "question_fields_truncated",
        "rd",
        "reserved_label",
    };

    toml::parse_result parsed = toml::parse_file(QUERY_ELIGIBILITY_VECTOR_FILE);
    REQUIRE(parsed);
    toml::table document = std::move(parsed).table();

    CHECK(document["format_version"].value<int64_t>() == 1);
    CHECK(document["generator"].value<std::string>() == "tests/vectors/query_eligibility/generate.py");

    const toml::array* vectors = document["vectors"].as_array();
    REQUIRE(vectors != nullptr);
    REQUIRE(vectors->size() == 19);

    std::set<std::string> covered_conditions;
    size_t eligible_count = 0;
    for (const toml::node& node: *vectors) {
        const toml::table* vector = node.as_table();
        REQUIRE(vector != nullptr);

        const auto name = (*vector)["name"].value<std::string>();
        const auto condition = (*vector)["condition"].value<std::string>();
        const auto message_hex = (*vector)["message_hex"].value<std::string>();
        const auto eligible = (*vector)["eligible"].value<bool>();
        REQUIRE(name.has_value());
        REQUIRE(condition.has_value());
        REQUIRE(message_hex.has_value());
        REQUIRE(eligible.has_value());
        CAPTURE(*name);

        CHECK(covered_conditions.insert(*condition).second);
        auto message = decode_hex(*message_hex);
        REQUIRE(message.has_value());
        CHECK(message->size() <= 512);

        const toml::table* question = (*vector)["question"].as_table();
        if (*eligible) {
            ++eligible_count;
            REQUIRE(question != nullptr);
            const auto name_wire_hex = (*question)["name_wire_hex"].value<std::string>();
            const auto type = (*question)["type"].value<int64_t>();
            const auto rr_class = (*question)["class"].value<int64_t>();
            REQUIRE(name_wire_hex.has_value());
            REQUIRE(type.has_value());
            REQUIRE(rr_class.has_value());
            CHECK(decode_hex(*name_wire_hex).has_value());
            CHECK(*type == 1);
            CHECK(*rr_class == 1);
        } else {
            CHECK(question == nullptr);
        }
    }

    CHECK(eligible_count == 1);
    CHECK(covered_conditions == expected_conditions);
}

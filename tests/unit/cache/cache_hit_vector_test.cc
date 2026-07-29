// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache_hit_reference.h"

#include <catch2/catch_test_macros.hpp>

#define TOML_EXCEPTIONS 0
#include <toml++/toml.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using shinku::cache::CacheLifetime;
using shinku::cache::CacheTime;
using shinku::cache::testing::apply_cache_hit;
using shinku::cache::testing::CacheHitInput;

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
    for (std::size_t offset = 0; offset < text.size(); offset += 2) {
        const uint8_t high = hex_nibble(text[offset]);
        const uint8_t low = hex_nibble(text[offset + 1]);
        if (high == 0xff || low == 0xff)
            return std::unexpected("hex string contains a non-hex character");
        result.push_back(static_cast<std::byte>((high << 4U) | low));
    }
    return result;
}

} // namespace

TEST_CASE("language-neutral Cache Hit vectors satisfy the reference semantics") {
    toml::parse_result parsed = toml::parse_file(CACHE_HIT_VECTOR_FILE);
    REQUIRE(parsed);
    toml::table document = std::move(parsed).table();

    CHECK(document["format_version"].value<int64_t>() == 1);
    CHECK(document["generator"].value<std::string>() == "tests/vectors/cache_hit/generate.py");

    const toml::array* vectors = document["vectors"].as_array();
    REQUIRE(vectors != nullptr);
    REQUIRE(vectors->size() == 4);

    for (const toml::node& node: *vectors) {
        const toml::table* vector = node.as_table();
        REQUIRE(vector != nullptr);

        const auto name = (*vector)["name"].value<std::string>();
        const auto response_hex = (*vector)["stored_response_hex"].value<std::string>();
        const auto query_hex = (*vector)["query_hex"].value<std::string>();
        const auto question_offset = (*vector)["question_offset"].value<int64_t>();
        const auto question_size = (*vector)["question_size"].value<int64_t>();
        const auto stored_at_ns = (*vector)["stored_at_ns"].value<int64_t>();
        const auto hit_at_ns = (*vector)["hit_at_ns"].value<int64_t>();
        const auto lifetime_seconds = (*vector)["lifetime_seconds"].value<int64_t>();
        const auto expected_hit = (*vector)["expected_hit"].value<bool>();
        REQUIRE(name.has_value());
        REQUIRE(response_hex.has_value());
        REQUIRE(query_hex.has_value());
        REQUIRE(question_offset.has_value());
        REQUIRE(question_size.has_value());
        REQUIRE(stored_at_ns.has_value());
        REQUIRE(hit_at_ns.has_value());
        REQUIRE(lifetime_seconds.has_value());
        REQUIRE(expected_hit.has_value());
        CAPTURE(*name);

        auto response = decode_hex(*response_hex);
        auto query = decode_hex(*query_hex);
        REQUIRE(response.has_value());
        REQUIRE(query.has_value());

        const toml::array* offsets_array = (*vector)["ttl_offsets"].as_array();
        REQUIRE(offsets_array != nullptr);
        std::vector<uint16_t> ttl_offsets;
        for (const toml::node& node: *offsets_array) {
            auto value = node.value<int64_t>();
            REQUIRE(value.has_value());
            REQUIRE(*value >= 0);
            REQUIRE(*value <= UINT16_MAX);
            ttl_offsets.push_back(static_cast<uint16_t>(*value));
        }

        CacheHitInput input {
            .response_template = *response,
            .query = *query,
            .question_offset = static_cast<std::size_t>(*question_offset),
            .question_size = static_cast<std::size_t>(*question_size),
            .ttl_offsets = ttl_offsets,
            .stored_at = CacheTime { std::chrono::nanoseconds(*stored_at_ns) },
            .lifetime = CacheLifetime(*lifetime_seconds),
        };
        auto actual = apply_cache_hit(input, CacheTime { std::chrono::nanoseconds(*hit_at_ns) });

        REQUIRE(actual.has_value());
        CHECK(actual->has_value() == *expected_hit);
        if (*expected_hit) {
            auto expected_hex = (*vector)["expected_response_hex"].value<std::string>();
            REQUIRE(expected_hex.has_value());
            auto expected = decode_hex(*expected_hex);
            REQUIRE(expected.has_value());
            CHECK(actual->value() == *expected);
        }
    }
}

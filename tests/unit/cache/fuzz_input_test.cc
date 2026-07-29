// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "fuzz_input.h"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace {

using shinku::cache::fuzzing::FuzzInput;

std::vector<uint8_t> octets(std::string_view text) {
    return { text.begin(), text.end() };
}

void check_decoded(std::string_view encoded) {
    const auto input = octets(encoded);
    const FuzzInput decoded(input.data(), input.size());
    const std::span<const std::byte> bytes = decoded.bytes();

    REQUIRE(bytes.size() == 3);
    CHECK(bytes[0] == std::byte { 0x00 });
    CHECK(bytes[1] == std::byte { 0x01 });
    CHECK(bytes[2] == std::byte { 0xff });
}

} // namespace

TEST_CASE("FuzzInput decodes hex corpus with common line endings") {
    SECTION("no line ending") {
        check_decoded("hex:0001ff");
    }

    SECTION("LF") {
        check_decoded("hex:0001ff\n");
    }

    SECTION("CRLF") {
        check_decoded("hex:0001ff\r\n");
    }
}

TEST_CASE("FuzzInput preserves invalid encoded corpus as raw bytes") {
    const auto input = octets("hex:0001fg\n");
    const FuzzInput decoded(input.data(), input.size());

    REQUIRE(decoded.bytes().size() == input.size());
    CHECK(decoded.bytes().front() == std::byte { 'h' });
    CHECK(decoded.bytes().back() == std::byte { '\n' });
}

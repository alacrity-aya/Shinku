// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/dns/wire_parser.h"

#include "fuzz_input.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace {

using shinku::cache::dns::kMaxTtlOffsets;
using shinku::cache::dns::parse_response;
using shinku::cache::fuzzing::FuzzInput;

[[noreturn]] void fail_property() {
    std::abort();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzInput input(data, size);
    std::array<uint16_t, kMaxTtlOffsets> first_offsets {};
    std::array<uint16_t, kMaxTtlOffsets> second_offsets {};

    auto first = parse_response(input.bytes(), first_offsets);
    auto second = parse_response(input.bytes(), second_offsets);
    if (first.has_value() != second.has_value())
        fail_property();
    if (!first) {
        if (first.error() != second.error())
            fail_property();
        return 0;
    }

    if (*first != *second)
        fail_property();

    for (uint16_t offset: first->ttl_offsets) {
        if (offset > input.bytes().size() || input.bytes().size() - offset < sizeof(uint32_t))
            fail_property();
    }
    return 0;
}

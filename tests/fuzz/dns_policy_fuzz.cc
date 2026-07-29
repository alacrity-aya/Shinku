// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/dns_policy.h"

#include "fuzz_input.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace {

using shinku::cache::CacheNamespace;
using shinku::cache::DnsPolicy;
using shinku::cache::fuzzing::FuzzInput;

[[noreturn]] void fail_property() {
    std::abort();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzInput input(data, size);
    constexpr CacheNamespace kNamespace { .destination_ipv4 = 0x7f00'0001U, .destination_port = 53 };
    DnsPolicy first_policy(512, true);
    DnsPolicy second_policy(512, true);

    auto first = first_policy.classify_response(input.bytes(), kNamespace);
    auto second = second_policy.classify_response(input.bytes(), kNamespace);
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

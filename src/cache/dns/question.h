// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/canonical_name.h"

#include <cstdint>

namespace shinku::cache::dns {

struct DnsQuestion {
    CanonicalDnsName name;
    uint16_t type = 0;
    uint16_t class_code = 0;

    friend bool operator==(const DnsQuestion&, const DnsQuestion&) noexcept = default;
};

} // namespace shinku::cache::dns

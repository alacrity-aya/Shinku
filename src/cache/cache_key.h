// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/canonical_name.h"

#include <cstdint>

namespace shinku::cache {

struct CacheNamespace {
    uint32_t destination_ipv4; // Host byte order.
    uint16_t destination_port; // Host byte order.

    bool operator==(const CacheNamespace&) const = default;
};

struct CacheKey {
    CacheNamespace cache_namespace;
    CanonicalDnsName question_name;
    uint16_t question_type;
    uint16_t question_class;

    bool operator==(const CacheKey&) const = default;
};

} // namespace shinku::cache

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/canonical_name.h"

#include <cstdint>

namespace shinku::cache::dns {

/**
 * @brief A single DNS question triple (name, type, class).
 *
 * Used to carry the parsed question section independently of the full response.
 */
struct DnsQuestion {
    CanonicalDnsName name; ///< Canonical owner name being queried.
    uint16_t type = 0; ///< DNS QTYPE of the question.
    uint16_t class_code = 0; ///< DNS QCLASS of the question.

    /// @brief Compares two questions by all members.
    friend bool operator==(const DnsQuestion&, const DnsQuestion&) noexcept = default;
};

} // namespace shinku::cache::dns

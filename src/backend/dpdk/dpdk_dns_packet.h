// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/dns/question.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_udp.h>
#include <span>

namespace shinku::backend::dpdk {

enum class DnsPacketDirection : uint8_t {
    Query,
    Response,
};

class ParsedDnsPacket final {
public:
    [[nodiscard]] static std::optional<ParsedDnsPacket>
    parse(std::span<const std::byte> frame, DnsPacketDirection direction) noexcept;

    [[nodiscard]] bool eligible_query() const noexcept;
    [[nodiscard]] bool eligible_response() const noexcept;

    [[nodiscard]] const rte_ether_hdr& ethernet() const noexcept;
    [[nodiscard]] const rte_ipv4_hdr& ipv4() const noexcept;
    [[nodiscard]] const rte_udp_hdr& udp() const noexcept;
    [[nodiscard]] std::span<const std::byte> dns_message() const noexcept;
    [[nodiscard]] std::span<const std::byte> encoded_question() const noexcept;
    [[nodiscard]] const cache::dns::DnsQuestion& question() const noexcept;
    // Returns the transaction ID in the network-order representation used by DpdkPendingKey.
    [[nodiscard]] uint16_t transaction_id_wire() const noexcept;

private:
    struct WireView {
        const rte_ether_hdr& ethernet;
        const rte_ipv4_hdr& ipv4;
        const rte_udp_hdr& udp;
        std::span<const std::byte> dns;
        std::span<const std::byte> encoded_question;
    };

    ParsedDnsPacket(WireView wire, cache::dns::DnsQuestion question) noexcept;

    WireView wire_;
    cache::dns::DnsQuestion question_;
};

} // namespace shinku::backend::dpdk

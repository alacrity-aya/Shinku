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

/// Whether a parsed packet is being interpreted as a query or a response.
enum class DnsPacketDirection : uint8_t {
    Query, ///< The packet is a DNS query (QR bit clear).
    Response, ///< The packet is a DNS response (QR bit set).
};

/**
 * @brief A parsed DNS-over-UDP/IPv4 Ethernet frame and its decoded question.
 *
 * ParsedDnsPacket overlays the Ethernet/IPv4/UDP headers of a received frame
 * and decodes the single question in the DNS message so the packet path can
 * correlate queries with responses and consult the cache.
 */
class ParsedDnsPacket final {
public:
    /**
     * @brief Parse a received Ethernet frame into a ParsedDnsPacket.
     *
     * @param frame The full Ethernet frame bytes.
     * @param direction Whether to interpret the message as a query or response.
     * @return The parsed packet, or empty if the frame was malformed or not DNS/UDP/IPv4.
     */
    [[nodiscard]] static std::optional<ParsedDnsPacket>
    parse(std::span<const std::byte> frame, DnsPacketDirection direction) noexcept;

    /// @return True if this packet is an eligible query (correct direction and parseable).
    [[nodiscard]] bool eligible_query() const noexcept;
    /// @return True if this packet is an eligible response (correct direction and parseable).
    [[nodiscard]] bool eligible_response() const noexcept;

    /// @return The Ethernet header of the frame.
    [[nodiscard]] const rte_ether_hdr& ethernet() const noexcept;
    /// @return The IPv4 header of the frame.
    [[nodiscard]] const rte_ipv4_hdr& ipv4() const noexcept;
    /// @return The UDP header of the frame.
    [[nodiscard]] const rte_udp_hdr& udp() const noexcept;
    /// @return A view of the DNS message payload (after the UDP header).
    [[nodiscard]] std::span<const std::byte> dns_message() const noexcept;
    /// @return A view of the wire-encoded question within the DNS message.
    [[nodiscard]] std::span<const std::byte> encoded_question() const noexcept;
    /// @return The decoded question triple.
    [[nodiscard]] const cache::dns::DnsQuestion& question() const noexcept;
    /// @return The transaction ID in the network-order representation used by @ref DpdkPendingKey.
    [[nodiscard]] uint16_t transaction_id_wire() const noexcept;

private:
    /// Borrowed view over the parsed headers and DNS payload of the frame.
    struct WireView {
        const rte_ether_hdr& ethernet;
        const rte_ipv4_hdr& ipv4;
        const rte_udp_hdr& udp;
        std::span<const std::byte> dns;
        std::span<const std::byte> encoded_question;
    };

    ParsedDnsPacket(WireView wire, cache::dns::DnsQuestion question) noexcept;

    WireView wire_; ///< Borrowed header/payload view.
    cache::dns::DnsQuestion question_; ///< Decoded question triple.
};

} // namespace shinku::backend::dpdk

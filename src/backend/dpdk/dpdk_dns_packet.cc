// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_dns_packet.h"

#include "cache/canonical_name.h"
#include "cache/dns/question.h"
#include "cache/dns/wire_io.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_udp.h>
#include <span>

namespace shinku::backend::dpdk {
namespace {

constexpr uint16_t kDnsPort = 53;
constexpr size_t kEthernetBytes = sizeof(rte_ether_hdr);
constexpr size_t kIpv4Bytes = sizeof(rte_ipv4_hdr);
constexpr size_t kUdpBytes = sizeof(rte_udp_hdr);
constexpr size_t kDnsOffset = kEthernetBytes + kIpv4Bytes + kUdpBytes;
constexpr size_t kDnsHeaderBytes = 12;

struct ParsedQuestion {
    cache::dns::DnsQuestion identity;
    std::span<const std::byte> encoded;
};

bool ethernet_unicast(const rte_ether_addr& address) noexcept {
    if ((address.addr_bytes[0] & 1U) != 0)
        return false;
    uint8_t any = 0;
    for (const uint8_t byte: address.addr_bytes)
        any |= byte;
    return any != 0;
}

bool ipv4_unicast(uint32_t address) noexcept {
    const uint32_t host = rte_be_to_cpu_32(address);
    return host != 0 && (host < 0xe0000000U || host > 0xefffffffU) && host != UINT32_MAX;
}

std::optional<ParsedQuestion> parse_question(std::span<const std::byte> dns) noexcept {
    if (dns.size() < kDnsHeaderBytes || cache::dns::wire::read_u16(dns, 4) != 1)
        return std::nullopt;

    size_t cursor = kDnsHeaderBytes;
    const size_t name_start = cursor;
    while (cursor < dns.size()) {
        const auto label_size = std::to_integer<uint8_t>(dns[cursor]);
        if ((label_size & 0xc0U) != 0 || label_size > 63)
            return std::nullopt;
        ++cursor;
        if (label_size == 0)
            break;
        if (label_size > dns.size() - cursor)
            return std::nullopt;
        cursor += label_size;
    }
    if (cursor <= name_start || dns.size() - cursor < 4)
        return std::nullopt;

    auto canonical = cache::CanonicalDnsName::from_wire(dns.subspan(name_start, cursor - name_start));
    if (!canonical)
        return std::nullopt;

    const size_t question_end = cursor + 4;
    return ParsedQuestion {
        .identity = {
            .name = *canonical,
            .type = cache::dns::wire::read_u16(dns, cursor),
            .class_code = cache::dns::wire::read_u16(dns, cursor + 2),
        },
        .encoded = dns.subspan(kDnsHeaderBytes, question_end - kDnsHeaderBytes),
    };
}

} // namespace

ParsedDnsPacket::ParsedDnsPacket(WireView wire, cache::dns::DnsQuestion question) noexcept:
    wire_(wire),
    question_(question) {}

std::optional<ParsedDnsPacket>
ParsedDnsPacket::parse(std::span<const std::byte> frame, DnsPacketDirection direction) noexcept {
    if (frame.size() < kDnsOffset)
        return std::nullopt;

    const auto& ethernet = *reinterpret_cast<const rte_ether_hdr*>(frame.data());
    if (ethernet.ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) || !ethernet_unicast(ethernet.dst_addr)
        || !ethernet_unicast(ethernet.src_addr))
        return std::nullopt;

    const auto& ipv4 = *reinterpret_cast<const rte_ipv4_hdr*>(frame.data() + kEthernetBytes);
    if (ipv4.version_ihl != RTE_IPV4_VHL_DEF || ipv4.next_proto_id != IPPROTO_UDP
        || (rte_be_to_cpu_16(ipv4.fragment_offset) & 0x3fffU) != 0)
        return std::nullopt;
    if (direction == DnsPacketDirection::Query && (!ipv4_unicast(ipv4.src_addr) || !ipv4_unicast(ipv4.dst_addr)))
        return std::nullopt;

    const auto& udp = *reinterpret_cast<const rte_udp_hdr*>(frame.data() + kEthernetBytes + kIpv4Bytes);
    const bool query = direction == DnsPacketDirection::Query;
    if (query ? rte_be_to_cpu_16(udp.dst_port) != kDnsPort : rte_be_to_cpu_16(udp.src_port) != kDnsPort)
        return std::nullopt;
    if (query ? udp.src_port == 0 : udp.dst_port == 0)
        return std::nullopt;

    const uint16_t total_length = rte_be_to_cpu_16(ipv4.total_length);
    const uint16_t udp_length = rte_be_to_cpu_16(udp.dgram_len);
    if (total_length != kIpv4Bytes + udp_length || udp_length < kUdpBytes + kDnsHeaderBytes
        || kDnsOffset + udp_length - kUdpBytes > frame.size())
        return std::nullopt;

    const std::span<const std::byte> dns(frame.data() + kDnsOffset, udp_length - kUdpBytes);
    auto question = parse_question(dns);
    if (!question)
        return std::nullopt;
    return ParsedDnsPacket(
        WireView {
            .ethernet = ethernet,
            .ipv4 = ipv4,
            .udp = udp,
            .dns = dns,
            .encoded_question = question->encoded,
        },
        question->identity
    );
}

bool ParsedDnsPacket::eligible_query() const noexcept {
    const uint16_t flags = cache::dns::wire::read_u16(wire_.dns, 2);
    return (flags & 0x8000U) == 0 && (flags & (0x7800U | 0x0200U | 0x0040U | 0x0020U | 0x0010U)) == 0
        && (flags & 0x0100U) != 0 && cache::dns::wire::read_u16(wire_.dns, 6) == 0
        && cache::dns::wire::read_u16(wire_.dns, 8) == 0 && cache::dns::wire::read_u16(wire_.dns, 10) == 0
        && question_.type == 1 && question_.class_code == 1
        && wire_.dns.size() == kDnsHeaderBytes + wire_.encoded_question.size();
}

bool ParsedDnsPacket::eligible_response() const noexcept {
    const uint16_t flags = cache::dns::wire::read_u16(wire_.dns, 2);
    const uint16_t rcode = flags & 0x000fU;
    return (flags & 0x8000U) != 0 && (flags & (0x7800U | 0x0200U | 0x0040U | 0x0010U)) == 0 && (flags & 0x0100U) != 0
        && (rcode == 0 || rcode == 3) && cache::dns::wire::read_u16(wire_.dns, 10) == 0 && question_.type == 1
        && question_.class_code == 1;
}

const rte_ether_hdr& ParsedDnsPacket::ethernet() const noexcept {
    return wire_.ethernet;
}

const rte_ipv4_hdr& ParsedDnsPacket::ipv4() const noexcept {
    return wire_.ipv4;
}

const rte_udp_hdr& ParsedDnsPacket::udp() const noexcept {
    return wire_.udp;
}

std::span<const std::byte> ParsedDnsPacket::dns_message() const noexcept {
    return wire_.dns;
}

std::span<const std::byte> ParsedDnsPacket::encoded_question() const noexcept {
    return wire_.encoded_question;
}

const cache::dns::DnsQuestion& ParsedDnsPacket::question() const noexcept {
    return question_;
}

uint16_t ParsedDnsPacket::transaction_id_wire() const noexcept {
    return rte_cpu_to_be_16(cache::dns::wire::read_u16(wire_.dns, 0));
}

} // namespace shinku::backend::dpdk

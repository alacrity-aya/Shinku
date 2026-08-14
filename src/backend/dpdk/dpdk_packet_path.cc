// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_packet_path.h"

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_cache_store.h"
#include "backend/dpdk/dpdk_dns_packet.h"
#include "backend/dpdk/dpdk_pending_store.h"
#include "backend/dpdk/dpdk_port.h"
#include "backend/dpdk/dpdk_time.h"
#include "cache/cache_key.h"
#include "cache/cache_time.h"
#include "cache/dns/wire_io.h"
#include "cache/dns/wire_parser.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_udp.h>
#include <span>
#include <spdlog/spdlog.h>

namespace shinku::backend::dpdk {
namespace {

constexpr uint16_t kBurstSize = 32;
constexpr size_t kEthernetBytes = sizeof(rte_ether_hdr);
constexpr size_t kIpv4Bytes = sizeof(rte_ipv4_hdr);
constexpr size_t kUdpBytes = sizeof(rte_udp_hdr);
constexpr size_t kDnsOffset = kEthernetBytes + kIpv4Bytes + kUdpBytes;
constexpr size_t kMaxFrameBytes = kDnsOffset + cache::dns::kMaxDnsMessageBytes;

bool satisfies_frame_contract(const rte_mbuf& packet) noexcept {
    constexpr uint32_t maximum_frame_bytes = RTE_ETHER_MAX_VLAN_FRAME_LEN - RTE_ETHER_CRC_LEN;
    return packet.nb_segs == 1 && packet.next == nullptr && packet.pkt_len == packet.data_len
        && packet.pkt_len <= maximum_frame_bytes;
}

DpdkPendingKey pending_key(const ParsedDnsPacket& packet) noexcept {
    return {
        .source_ipv4 = packet.ipv4().src_addr,
        .destination_ipv4 = packet.ipv4().dst_addr,
        .source_port = packet.udp().src_port,
        .destination_port = packet.udp().dst_port,
        .transaction_id = packet.transaction_id_wire(),
    };
}

cache::CacheKey cache_key(const ParsedDnsPacket& packet) noexcept {
    return {
        .cache_namespace = {
            .destination_ipv4 = rte_be_to_cpu_32(packet.ipv4().dst_addr),
            .destination_port = rte_be_to_cpu_16(packet.udp().dst_port),
        },
        .question_name = packet.question().name,
        .question_type = packet.question().type,
        .question_class = packet.question().class_code,
    };
}

bool build_hit(
    rte_mbuf& packet,
    const ParsedDnsPacket& query,
    const DpdkCacheStore::Entry& entry,
    cache::CacheTime now
) {
    if (now < entry.stored_at || now >= entry.expires_at)
        return false;
    std::array<std::byte, kMaxFrameBytes> frame {};
    const size_t frame_size = kDnsOffset + entry.response_size;
    if (frame_size > frame.size() || entry.response_size < 12
        || 12 + query.encoded_question().size() > entry.response_size)
        return false;
    auto* ethernet = reinterpret_cast<rte_ether_hdr*>(frame.data());
    ethernet->dst_addr = query.ethernet().src_addr;
    ethernet->src_addr = query.ethernet().dst_addr;
    ethernet->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    auto* ipv4 = reinterpret_cast<rte_ipv4_hdr*>(frame.data() + kEthernetBytes);
    *ipv4 = {};
    ipv4->version_ihl = RTE_IPV4_VHL_DEF;
    ipv4->total_length = rte_cpu_to_be_16(static_cast<uint16_t>(kIpv4Bytes + kUdpBytes + entry.response_size));
    ipv4->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
    ipv4->time_to_live = 64;
    ipv4->next_proto_id = IPPROTO_UDP;
    ipv4->src_addr = query.ipv4().dst_addr;
    ipv4->dst_addr = query.ipv4().src_addr;
    auto* udp = reinterpret_cast<rte_udp_hdr*>(frame.data() + kEthernetBytes + kIpv4Bytes);
    udp->src_port = query.udp().dst_port;
    udp->dst_port = query.udp().src_port;
    udp->dgram_len = rte_cpu_to_be_16(static_cast<uint16_t>(kUdpBytes + entry.response_size));
    udp->dgram_cksum = 0;
    std::memcpy(frame.data() + kDnsOffset, entry.response.data(), entry.response_size);
    std::memcpy(frame.data() + kDnsOffset, query.dns_message().data(), 2);
    std::memcpy(frame.data() + kDnsOffset + 12, query.encoded_question().data(), query.encoded_question().size());
    const auto elapsed =
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now - entry.stored_at).count());
    for (const uint16_t offset: std::span(entry.ttl_offsets.data(), entry.ttl_offset_count)) {
        if (offset > entry.response_size || entry.response_size - offset < 4)
            return false;
        auto dns = std::span(frame).subspan(kDnsOffset, entry.response_size);
        uint32_t ttl = cache::dns::wire::read_u32(dns, offset);
        ttl = ttl > elapsed ? ttl - static_cast<uint32_t>(elapsed) : 0;
        cache::dns::wire::write_u32(dns, offset, ttl);
    }
    ipv4->hdr_checksum = 0;
    ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
    if (frame_size > packet.data_len) {
        if (rte_pktmbuf_append(&packet, static_cast<uint16_t>(frame_size - packet.data_len)) == nullptr)
            return false;
    } else if (
        frame_size < packet.data_len
        && rte_pktmbuf_trim(&packet, static_cast<uint16_t>(packet.data_len - frame_size)) != 0
    )
    {
        return false;
    }
    std::memcpy(rte_pktmbuf_mtod(&packet, void*), frame.data(), frame_size);
    packet.ol_flags &= RTE_MBUF_F_EXTERNAL | RTE_MBUF_F_INDIRECT;
    packet.packet_type = 0;
    packet.vlan_tci = 0;
    packet.vlan_tci_outer = 0;
    std::memset(&packet.hash, 0, sizeof(packet.hash));
    packet.tx_offload = 0;
    return true;
}

} // namespace

DpdkPacketForwarder::DpdkPacketForwarder(
    DpdkPort& source,
    DpdkPort& destination,
    DnsPacketDirection direction,
    DpdkCacheContext& cache_context
) noexcept:
    source_(source),
    destination_(destination),
    direction_(direction),
    cache_context_(&cache_context) {}

DpdkPacketForwarder::DpdkPacketForwarder(DpdkPort& source, DpdkPort& destination, DnsPacketDirection direction) noexcept
    :
    source_(source),
    destination_(destination),
    direction_(direction),
    cache_context_(nullptr) {}

void DpdkPacketForwarder::warn_frame_violation(const rte_mbuf* packet) {
    if (frame_warning_emitted_)
        return;
    if (packet == nullptr) {
        spdlog::warn("DPDK port {} dropped a frame-contract violation: null_mbuf=true", source_.identity());
    } else {
        spdlog::warn(
            "DPDK port {} dropped a frame-contract violation: nb_segs={} pkt_len={} data_len={} next_present={}",
            source_.identity(),
            packet->nb_segs,
            packet->pkt_len,
            packet->data_len,
            packet->next != nullptr
        );
    }
    frame_warning_emitted_ = true;
}

DpdkPacketForwarder::PacketDisposition
DpdkPacketForwarder::process_query(rte_mbuf& packet, const ParsedDnsPacket& query) {
    auto now = read_dpdk_boot_time();
    if (!now) {
        if (!time_warning_emitted_) {
            spdlog::warn("DPDK client packet skipped cache work after a CLOCK_BOOTTIME read failure");
            time_warning_emitted_ = true;
        }
        return PacketDisposition::Forward;
    }

    DpdkCacheContext& context = *cache_context_;
    const auto key = cache_key(query);
    if (const auto* entry = context.cache.lookup(key, *now); entry != nullptr && build_hit(packet, query, *entry, *now))
    {
        return PacketDisposition::Reply;
    }

    const auto _ = context.pending.remember(pending_key(query), query.question(), *now);
    return PacketDisposition::Forward;
}

void DpdkPacketForwarder::observe_response(const ParsedDnsPacket& response) {
    auto now = read_dpdk_boot_time();
    if (!now) {
        if (!time_warning_emitted_) {
            spdlog::warn("DPDK service packet skipped cache work after a CLOCK_BOOTTIME read failure");
            time_warning_emitted_ = true;
        }
        return;
    }

    const auto response_key = pending_key(response);
    const DpdkPendingKey query_key {
        .source_ipv4 = response_key.destination_ipv4,
        .destination_ipv4 = response_key.source_ipv4,
        .source_port = response_key.destination_port,
        .destination_port = response_key.source_port,
        .transaction_id = response_key.transaction_id,
    };
    DpdkCacheContext& context = *cache_context_;
    auto claimed = context.pending.claim(query_key, response.question(), *now, context.pending_timeout);
    if (!claimed.value_or(false))
        return;

    const cache::CacheNamespace cache_namespace {
        .destination_ipv4 = rte_be_to_cpu_32(query_key.destination_ipv4),
        .destination_port = rte_be_to_cpu_16(query_key.destination_port),
    };
    auto candidate = context.policy.classify_response(response.dns_message(), cache_namespace);
    if (!candidate)
        return;
    auto _ = context.cache.store(*candidate, *now, *now);
}

DpdkPacketForwarder::PacketDisposition DpdkPacketForwarder::disposition(rte_mbuf* packet) {
    if (packet == nullptr || !satisfies_frame_contract(*packet)) {
        warn_frame_violation(packet);
        return PacketDisposition::Drop;
    }
    if (cache_context_ == nullptr)
        return PacketDisposition::Forward;

    const std::span<const std::byte> frame(rte_pktmbuf_mtod(packet, const std::byte*), packet->data_len);
    auto parsed = ParsedDnsPacket::parse(frame, direction_);
    if (!parsed)
        return PacketDisposition::Forward;
    if (direction_ == DnsPacketDirection::Query)
        return parsed->eligible_query() ? process_query(*packet, *parsed) : PacketDisposition::Forward;
    if (parsed->eligible_response())
        observe_response(*parsed);
    return PacketDisposition::Forward;
}

void DpdkPacketForwarder::transmit_or_release(DpdkPort& destination, std::span<rte_mbuf*> packets) {
    if (packets.empty())
        return;
    const uint16_t accepted = destination.transmit(packets);
    for (rte_mbuf* packet: packets.subspan(accepted))
        source_.free_packet(*packet);
}

std::expected<void, BackendError> DpdkPacketForwarder::run() {
    std::array<rte_mbuf*, kBurstSize> received {};
    const uint16_t received_count = source_.receive(received);
    uint16_t forward_count = 0;
    for (rte_mbuf* packet: std::span(received).first(received_count)) {
        switch (disposition(packet)) {
            case PacketDisposition::Forward:
                received[forward_count++] = packet;
                break;
            case PacketDisposition::Reply: {
                std::array reply { packet };
                transmit_or_release(source_, reply);
                break;
            }
            case PacketDisposition::Drop:
                if (packet != nullptr)
                    source_.free_packet(*packet);
                break;
        }
    }
    transmit_or_release(destination_, std::span(received).first(forward_count));
    return {};
}

} // namespace shinku::backend::dpdk

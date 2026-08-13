// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_packet_path.h"

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_native_session.h"

#include <array>
#include <cstdint>
#include <expected>
#include <rte_ether.h>
#include <rte_mbuf_core.h>
#include <spdlog/spdlog.h>

namespace shinku::backend::dpdk {
namespace {

constexpr uint16_t kBurstSize = 32;

bool satisfies_frame_contract(const rte_mbuf& packet) noexcept {
    constexpr uint32_t maximum_frame_bytes = RTE_ETHER_MAX_VLAN_FRAME_LEN - RTE_ETHER_CRC_LEN;
    return packet.nb_segs == 1 && packet.next == nullptr && packet.pkt_len == packet.data_len
        && packet.pkt_len <= maximum_frame_bytes;
}

} // namespace

DpdkPacketPath::DpdkPacketPath(DpdkNativeSession& session, PortSide source, PortSide destination) noexcept:
    session_(&session),
    source_(source),
    destination_(destination) {}

std::expected<void, BackendError> DpdkPacketPath::run() {
    std::array<rte_mbuf*, kBurstSize> received {};
    const uint16_t received_count = session_->receive(source_, received.data(), kBurstSize);

    uint16_t valid_count = 0;
    for (uint16_t index = 0; index < received_count; ++index) {
        rte_mbuf* packet = received[index];
        if (packet != nullptr && satisfies_frame_contract(*packet)) {
            received[valid_count++] = packet;
            continue;
        }

        if (!frame_warning_emitted_) {
            const uint16_t segments = packet == nullptr ? 0 : packet->nb_segs;
            const uint32_t packet_length = packet == nullptr ? 0 : packet->pkt_len;
            spdlog::warn(
                "DPDK port {} dropped a frame-contract violation (segments={}, packet_length={})",
                session_->port_identity(source_),
                segments,
                packet_length
            );
            frame_warning_emitted_ = true;
        }
        if (packet != nullptr)
            session_->free_packet(packet);
    }

    if (valid_count == 0)
        return {};

    const uint16_t accepted = session_->transmit(destination_, received.data(), valid_count);
    for (uint16_t index = accepted; index < valid_count; ++index)
        session_->free_packet(received[index]);
    return {};
}

} // namespace shinku::backend::dpdk

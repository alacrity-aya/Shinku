// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_dns_packet.h"
#include "cache/dns_policy.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <span>

struct rte_mbuf;

namespace shinku::backend::dpdk {

class DpdkCacheStore;
class DpdkPendingStore;
class DpdkPort;

struct DpdkCacheContext {
    DpdkCacheStore& cache;
    DpdkPendingStore& pending;
    cache::DnsPolicy& policy;
    std::chrono::nanoseconds pending_timeout {};
    std::chrono::nanoseconds cache_cleanup_interval {};
    bool maintenance_time_warning_emitted = false;
};

class DpdkPollTask {
public:
    virtual ~DpdkPollTask() = default;
    [[nodiscard]] virtual std::expected<void, BackendError> run() = 0;
};

class DpdkPacketForwarder final: public DpdkPollTask {
public:
    DpdkPacketForwarder(
        DpdkPort& source,
        DpdkPort& destination,
        DnsPacketDirection direction,
        DpdkCacheContext& cache_context
    ) noexcept;
    DpdkPacketForwarder(DpdkPort& source, DpdkPort& destination, DnsPacketDirection direction) noexcept;

    [[nodiscard]] std::expected<void, BackendError> run() override;

private:
    enum class PacketDisposition : uint8_t {
        Forward,
        Reply,
        Drop,
    };

    void warn_frame_violation(const rte_mbuf* packet);
    [[nodiscard]] PacketDisposition disposition(rte_mbuf* packet);
    [[nodiscard]] PacketDisposition process_query(rte_mbuf& packet, const ParsedDnsPacket& query);
    void observe_response(const ParsedDnsPacket& response);
    void transmit_or_release(DpdkPort& destination, std::span<rte_mbuf*> packets);

    DpdkPort& source_;
    DpdkPort& destination_;
    DnsPacketDirection direction_;
    bool frame_warning_emitted_ = false;
    bool time_warning_emitted_ = false;
    DpdkCacheContext* cache_context_;
};

} // namespace shinku::backend::dpdk

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

/// Shared state for the DPDK cache and pending-query subsystems during a run.
struct DpdkCacheContext {
    DpdkCacheStore& cache; ///< The cache store.
    DpdkPendingStore& pending; ///< The pending-query store.
    cache::DnsPolicy& policy; ///< The DNS cache policy.
    std::chrono::nanoseconds pending_timeout {}; ///< How long a pending query may remain unresolved.
    std::chrono::nanoseconds cache_cleanup_interval {}; ///< Interval between cache cleanup sweeps.
    bool maintenance_time_warning_emitted = false; ///< True once a clock-time warning has been logged.
};

/// Abstract unit of cooperative work driven by the scheduler each quantum.
class DpdkPollTask {
public:
    virtual ~DpdkPollTask() = default;
    /// @brief Perform one iteration of this task's work.
    /// @return Void on success, or a @ref BackendError if the task failed.
    [[nodiscard]] virtual std::expected<void, BackendError> run() = 0;
};

/**
 * @brief Forwards DNS packets between two ports, consulting the cache.
 *
 * On each @ref run the forwarder receives a burst from `source_`, classifies
 * each packet as a query or response, and either forwards it to `destination_`,
 * replies from the cache, or drops it. When a @ref DpdkCacheContext
 * is supplied the forwarder also populates the cache from observed responses
 * and consults the pending-query store.
 */
class DpdkPacketForwarder final: public DpdkPollTask {
public:
    /// @brief Construct a forwarding path that participates in cache/pending bookkeeping.
    DpdkPacketForwarder(
        DpdkPort& source,
        DpdkPort& destination,
        DnsPacketDirection direction,
        DpdkCacheContext& cache_context
    ) noexcept;
    /// @brief Construct a forwarding path with no cache participation (pass-through).
    DpdkPacketForwarder(DpdkPort& source, DpdkPort& destination, DnsPacketDirection direction) noexcept;

    [[nodiscard]] std::expected<void, BackendError> run() override;

private:
    /// Disposition of a single packet inspected by @ref disposition.
    enum class PacketDisposition : uint8_t {
        Forward, ///< Forward the packet to the destination port.
        Reply, ///< Reply from the cache; do not forward.
        Drop, ///< Drop the packet.
    };

    void warn_frame_violation(const rte_mbuf* packet);
    [[nodiscard]] PacketDisposition disposition(rte_mbuf* packet);
    [[nodiscard]] PacketDisposition process_query(rte_mbuf& packet, const ParsedDnsPacket& query);
    void observe_response(const ParsedDnsPacket& response);
    void transmit_or_release(DpdkPort& destination, std::span<rte_mbuf*> packets);

    DpdkPort& source_; ///< Port packets are received from.
    DpdkPort& destination_; ///< Port packets are forwarded to.
    DnsPacketDirection direction_; ///< Whether this path carries queries or responses.
    bool frame_warning_emitted_ = false; ///< True once a frame-size warning has been logged.
    bool time_warning_emitted_ = false; ///< True once a clock-time warning has been logged.
    DpdkCacheContext* cache_context_; ///< Cache context, or null for pass-through mode.
};

} // namespace shinku::backend::dpdk

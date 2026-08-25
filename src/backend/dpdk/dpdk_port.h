// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_error.h"
#include "backend/dpdk/dpdk_packet_pool.h"

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

struct rte_mbuf;

namespace shinku::backend::dpdk {

class ProductionDpdkEal;
class ProductionDpdkPacketPool;

/**
 * @brief Abstract DPDK Ethernet port.
 *
 * Exposes the configure/queue/start lifecycle plus RX/TX primitives used by
 * the packet path. Concrete implementations wrap a real DPDK ethdev port.
 */
class DpdkPort {
public:
    virtual ~DpdkPort() = default;

    DpdkPort(const DpdkPort&) = delete;
    DpdkPort& operator=(const DpdkPort&) = delete;
    DpdkPort(DpdkPort&&) = delete;
    DpdkPort& operator=(DpdkPort&&) = delete;

    /// @brief Configure the port and report the RX/TX descriptor counts in use.
    [[nodiscard]] virtual std::expected<DpdkDescriptorCounts, DpdkError> configure() = 0;
    /// @brief Set up RX/TX queues, falling back to @p fallback_socket_id for NUMA placement.
    [[nodiscard]] virtual std::expected<void, DpdkError> setup_queues(int fallback_socket_id) = 0;
    /// @brief Start the port (and any promiscuous/link setup) for packet I/O.
    [[nodiscard]] virtual std::expected<void, DpdkError> start() = 0;
    /// @brief Log the current link state for operator diagnostics.
    virtual void log_link_state() const noexcept = 0;

    /// @brief Receive up to @p packets.size() mbufs into @p packets.
    /// @return The number of packets actually received.
    [[nodiscard]] virtual uint16_t receive(std::span<rte_mbuf*> packets) noexcept = 0;
    /// @brief Transmit up to @p packets.size() mbufs from @p packets.
    /// @return The number of packets actually transmitted.
    [[nodiscard]] virtual uint16_t transmit(std::span<rte_mbuf*> packets) noexcept = 0;
    /// @brief Return a single mbuf to the pool.
    virtual void free_packet(rte_mbuf& packet) noexcept = 0;
    /// @return A stable human-readable identifier for this port.
    [[nodiscard]] virtual std::string_view identity() const noexcept = 0;

    /// @return True if this port owns the underlying ethdev resources.
    [[nodiscard]] virtual bool owns_resources() const noexcept = 0;
    /// @brief Stop and release the ethdev if owned.
    [[nodiscard]] virtual std::expected<void, DpdkError> close() = 0;

protected:
    DpdkPort() = default;
};

/**
 * @brief Production @ref DpdkPort backed by a real DPDK ethdev.
 *
 * Coordinates ethdev ownership with the @ref ProductionDpdkEal so cleanup
 * ordering across EAL, ports, and the packet pool is consistent.
 */
class ProductionDpdkPort final: public DpdkPort {
public:
    /// @brief Construct a port wrapping ethdev @p id with a human-readable @p identity.
    ProductionDpdkPort(
        uint16_t id,
        std::string identity,
        ProductionDpdkEal& eal,
        ProductionDpdkPacketPool& packet_pool
    ) noexcept;
    ~ProductionDpdkPort() override;

    [[nodiscard]] std::expected<DpdkDescriptorCounts, DpdkError> configure() override;
    [[nodiscard]] std::expected<void, DpdkError> setup_queues(int fallback_socket_id) override;
    [[nodiscard]] std::expected<void, DpdkError> start() override;
    void log_link_state() const noexcept override;

    [[nodiscard]] uint16_t receive(std::span<rte_mbuf*> packets) noexcept override;
    [[nodiscard]] uint16_t transmit(std::span<rte_mbuf*> packets) noexcept override;
    void free_packet(rte_mbuf& packet) noexcept override;
    [[nodiscard]] std::string_view identity() const noexcept override;

    [[nodiscard]] bool owns_resources() const noexcept override;
    [[nodiscard]] std::expected<void, DpdkError> close() override;

private:
    uint16_t id_; ///< DPDK ethdev port id.
    std::string identity_; ///< Human-readable port identity for logs.
    ProductionDpdkEal& eal_; ///< Owning EAL, for coordinated cleanup.
    ProductionDpdkPacketPool& packet_pool_; ///< Pool packets are allocated from.
    DpdkDescriptorCounts descriptors_ {}; ///< RX/TX descriptor counts in use.
    bool configured_ = false; ///< True once @ref configure has succeeded.
    bool started_ = false; ///< True once @ref start has succeeded.
    bool promiscuous_ = false; ///< True if the port was put into promiscuous mode.
};

} // namespace shinku::backend::dpdk

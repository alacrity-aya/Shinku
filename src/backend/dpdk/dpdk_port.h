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

class DpdkPort {
public:
    virtual ~DpdkPort() = default;

    DpdkPort(const DpdkPort&) = delete;
    DpdkPort& operator=(const DpdkPort&) = delete;
    DpdkPort(DpdkPort&&) = delete;
    DpdkPort& operator=(DpdkPort&&) = delete;

    [[nodiscard]] virtual std::expected<DpdkDescriptorCounts, DpdkError> configure() = 0;
    [[nodiscard]] virtual std::expected<void, DpdkError> setup_queues(int fallback_socket_id) = 0;
    [[nodiscard]] virtual std::expected<void, DpdkError> start() = 0;
    virtual void log_link_state() const noexcept = 0;

    [[nodiscard]] virtual uint16_t receive(std::span<rte_mbuf*> packets) noexcept = 0;
    [[nodiscard]] virtual uint16_t transmit(std::span<rte_mbuf*> packets) noexcept = 0;
    virtual void free_packet(rte_mbuf& packet) noexcept = 0;
    [[nodiscard]] virtual std::string_view identity() const noexcept = 0;

    [[nodiscard]] virtual bool owns_resources() const noexcept = 0;
    [[nodiscard]] virtual std::expected<void, DpdkError> close() = 0;

protected:
    DpdkPort() = default;
};

class ProductionDpdkPort final: public DpdkPort {
public:
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
    uint16_t id_;
    std::string identity_;
    ProductionDpdkEal& eal_;
    ProductionDpdkPacketPool& packet_pool_;
    DpdkDescriptorCounts descriptors_ {};
    bool configured_ = false;
    bool started_ = false;
    bool promiscuous_ = false;
};

} // namespace shinku::backend::dpdk

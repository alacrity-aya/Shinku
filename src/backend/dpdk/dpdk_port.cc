// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_port.h"

#include "backend/dpdk/dpdk_eal.h"
#include "backend/dpdk/dpdk_error.h"
#include "backend/dpdk/dpdk_packet_pool.h"

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <expected>
#include <format>
#include <limits>
#include <optional>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <span>
#include <spdlog/spdlog.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace shinku::backend::dpdk {
namespace {

constexpr uint16_t kRequestedRxDescriptors = 1024;
constexpr uint16_t kRequestedTxDescriptors = 1024;
constexpr uint16_t kMinimumDescriptors = 32;
constexpr uint16_t kFrameMtu = 1500;
constexpr uint16_t kQueueId = 0;

std::error_code result_error(int result) noexcept {
    return { -result, std::generic_category() };
}

std::unexpected<DpdkError>
failure(std::string operation, std::string detail, std::optional<std::error_code> cause = std::nullopt) {
    return std::unexpected(DpdkError {
        .operation = std::move(operation),
        .detail = std::move(detail),
        .cause = cause,
    });
}

} // namespace

ProductionDpdkPort::ProductionDpdkPort(
    uint16_t id,
    std::string identity,
    ProductionDpdkEal& eal,
    ProductionDpdkPacketPool& packet_pool
) noexcept:
    id_(id),
    identity_(std::move(identity)),
    eal_(eal),
    packet_pool_(packet_pool) {}

ProductionDpdkPort::~ProductionDpdkPort() {
    auto _ = close();
}

std::expected<DpdkDescriptorCounts, DpdkError> ProductionDpdkPort::configure() {
    if (rte_eth_dev_is_valid_port(id_) == 0) {
        return failure(
            "port validation",
            std::format("configured DPDK Port ID {} ({}) does not exist", id_, identity_)
        );
    }

    rte_eth_dev_info info {};
    int result = rte_eth_dev_info_get(id_, &info);
    if (result != 0)
        return failure("port capability query", identity_, result_error(result));
    if (info.max_rx_queues < 1 || info.max_tx_queues < 1)
        return failure("port capability validation", std::format("{} does not provide one RX and one TX queue", identity_));
    if (kFrameMtu < info.min_mtu || (info.max_mtu != 0 && kFrameMtu > info.max_mtu)) {
        return failure(
            "port MTU validation",
            std::format("{} does not support the required {}-byte MTU", identity_, kFrameMtu)
        );
    }

    rte_eth_conf port_config {}; // NOLINT(bugprone-invalid-enum-default-initialization)
    port_config.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    port_config.rxmode.mtu = kFrameMtu;
    port_config.rxmode.offloads = 0;
    port_config.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    port_config.txmode.offloads = 0;
    result = rte_eth_dev_configure(id_, 1, 1, &port_config);
    if (result != 0)
        return failure("port configuration", identity_, result_error(result));
    configured_ = true;
    eal_.acquire_port();

    uint16_t actual_mtu = 0;
    result = rte_eth_dev_get_mtu(id_, &actual_mtu);
    if (result != 0)
        return failure("port MTU query", identity_, result_error(result));
    if (actual_mtu != kFrameMtu) {
        result = rte_eth_dev_set_mtu(id_, kFrameMtu);
        if (result != 0)
            return failure("port MTU configuration", identity_, result_error(result));
    }

    uint16_t rx_descriptors = kRequestedRxDescriptors;
    uint16_t tx_descriptors = kRequestedTxDescriptors;
    result = rte_eth_dev_adjust_nb_rx_tx_desc(id_, &rx_descriptors, &tx_descriptors);
    if (result != 0)
        return failure("descriptor adjustment", identity_, result_error(result));
    if (rx_descriptors < kMinimumDescriptors || tx_descriptors < kMinimumDescriptors) {
        return failure(
            "descriptor validation",
            std::format(
                "{} adjusted descriptors below {} (RX={}, TX={})",
                identity_,
                kMinimumDescriptors,
                rx_descriptors,
                tx_descriptors
            )
        );
    }
    descriptors_ = { .rx = rx_descriptors, .tx = tx_descriptors };
    return descriptors_;
}

std::expected<void, DpdkError> ProductionDpdkPort::setup_queues(int fallback_socket_id) {
    rte_eth_dev_info info {};
    int result = rte_eth_dev_info_get(id_, &info);
    if (result != 0)
        return failure("queue capability query", identity_, result_error(result));

    const int port_socket = rte_eth_dev_socket_id(id_);
    const auto queue_socket = static_cast<unsigned>(port_socket >= 0 ? port_socket : fallback_socket_id);
    rte_eth_rxconf rx_config = info.default_rxconf;
    rx_config.offloads = 0;
    result = rte_eth_rx_queue_setup(
        id_,
        kQueueId,
        descriptors_.rx,
        queue_socket,
        &rx_config,
        &packet_pool_.native_pool()
    );
    if (result != 0)
        return failure("RX queue setup", identity_, result_error(result));

    rte_eth_txconf tx_config = info.default_txconf;
    tx_config.offloads = 0;
    result = rte_eth_tx_queue_setup(id_, kQueueId, descriptors_.tx, queue_socket, &tx_config);
    if (result != 0)
        return failure("TX queue setup", identity_, result_error(result));
    return {};
}

std::expected<void, DpdkError> ProductionDpdkPort::start() {
    int result = rte_eth_dev_start(id_);
    if (result != 0)
        return failure("port start", identity_, result_error(result));
    started_ = true;

    result = rte_eth_promiscuous_enable(id_);
    if (result != 0)
        return failure("promiscuous-mode enable", identity_, result_error(result));
    promiscuous_ = true;

    result = rte_eth_promiscuous_get(id_);
    if (result < 0)
        return failure("promiscuous-mode query", identity_, result_error(result));
    if (result == 0)
        return failure("promiscuous-mode verification", identity_);
    return {};
}

void ProductionDpdkPort::log_link_state() const noexcept {
    rte_eth_link link {};
    const int result = rte_eth_link_get_nowait(id_, &link);
    if (result != 0) {
        spdlog::warn("DPDK port {} link query failed: {}", identity_, result_error(result).message());
        return;
    }
    if (link.link_status == RTE_ETH_LINK_UP) {
        spdlog::info(
            "DPDK port {} link is up (speed={} Mbps, duplex={})",
            identity_,
            link.link_speed,
            link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "full" : "half"
        );
    } else {
        spdlog::warn("DPDK port {} link is down; startup continues", identity_);
    }
}

uint16_t ProductionDpdkPort::receive(std::span<rte_mbuf*> packets) noexcept {
    assert(packets.size() <= std::numeric_limits<uint16_t>::max());
    return rte_eth_rx_burst(id_, kQueueId, packets.data(), static_cast<uint16_t>(packets.size()));
}

uint16_t ProductionDpdkPort::transmit(std::span<rte_mbuf*> packets) noexcept {
    assert(packets.size() <= std::numeric_limits<uint16_t>::max());
    return rte_eth_tx_burst(id_, kQueueId, packets.data(), static_cast<uint16_t>(packets.size()));
}

void ProductionDpdkPort::free_packet(rte_mbuf& packet) noexcept {
    rte_pktmbuf_free(&packet);
}

std::string_view ProductionDpdkPort::identity() const noexcept {
    return identity_;
}

bool ProductionDpdkPort::owns_resources() const noexcept {
    return configured_;
}

std::expected<void, DpdkError> ProductionDpdkPort::close() {
    if (!configured_)
        return {};

    if (promiscuous_) {
        const int result = rte_eth_promiscuous_disable(id_);
        if (result != 0 && result != -ENOTSUP)
            return failure("promiscuous-mode disable", identity_, result_error(result));
        promiscuous_ = false;
    }
    if (started_) {
        const int result = rte_eth_dev_stop(id_);
        if (result != 0)
            return failure("port stop", identity_, result_error(result));
        started_ = false;
    }
    const int result = rte_eth_dev_close(id_);
    if (result != 0)
        return failure("port close", identity_, result_error(result));
    configured_ = false;
    eal_.release_port();
    return {};
}

} // namespace shinku::backend::dpdk

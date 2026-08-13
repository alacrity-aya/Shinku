// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_native_session.h"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <expected>
#include <format>
#include <memory>
#include <optional>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <span>
#include <spdlog/spdlog.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace shinku::backend::dpdk {
namespace {

constexpr uint16_t kRequestedRxDescriptors = 1024;
constexpr uint16_t kRequestedTxDescriptors = 1024;
constexpr uint16_t kMinimumDescriptors = 32;
constexpr uint16_t kFrameMtu = 1500;
constexpr unsigned kMempoolCacheSize = 256;
constexpr unsigned kBurstAllowance = 2 * 32;
constexpr uint16_t kQueueId = 0;
constexpr uint16_t kClientPortId = 0;
constexpr uint16_t kServicePortId = 1;
constexpr uint16_t kRequiredPortCount = 2;

struct DescriptorCounts {
    uint16_t rx;
    uint16_t tx;
};

std::optional<std::error_code> dpdk_errno() noexcept {
    if (rte_errno == 0)
        return std::nullopt;
    return std::error_code(rte_errno, std::generic_category());
}

std::error_code result_error(int result) noexcept {
    return { -result, std::generic_category() };
}

std::unexpected<DpdkNativeError>
native_failure(std::string operation, std::string detail, std::optional<std::error_code> cause = std::nullopt) {
    return std::unexpected(
        DpdkNativeError {
            .operation = std::move(operation),
            .detail = std::move(detail),
            .cause = cause,
        }
    );
}

unsigned packet_pool_capacity(const std::array<DescriptorCounts, 2>& descriptors) noexcept {
    unsigned required = kBurstAllowance + kMempoolCacheSize;
    for (const DescriptorCounts counts: descriptors) {
        required += counts.rx;
        required += counts.tx;
    }

    unsigned power_of_two = 1;
    while (power_of_two - 1 < required)
        power_of_two *= 2;
    return power_of_two - 1;
}

} // namespace

struct ProductionDpdkNativeSession::Resources {
    struct Port {
        uint16_t id = 0;
        std::string identity;
        DescriptorCounts descriptors {};
        bool configured = false;
        bool started = false;
        bool promiscuous = false;
    };

    Port client;
    Port service;
    rte_mempool* packet_pool = nullptr;
    bool eal_initialized = false;
    bool eal_cleanup_attempted = false;
    std::optional<DpdkNativeError> terminal_cleanup_error;
    int main_socket = SOCKET_ID_ANY;

    [[nodiscard]] auto&& port(this auto&& self, PortSide side) noexcept {
        return side == PortSide::Client ? self.client : self.service;
    }
};

namespace {

std::expected<void, DpdkNativeError> configure_port(ProductionDpdkNativeSession::Resources::Port& port) {
    if (rte_eth_dev_is_valid_port(port.id) == 0) {
        return native_failure(
            "port validation",
            std::format("configured DPDK Port ID {} ({}) does not exist", port.id, port.identity)
        );
    }

    rte_eth_dev_info info {};
    int result = rte_eth_dev_info_get(port.id, &info);
    if (result != 0)
        return native_failure("port capability query", port.identity, result_error(result));
    if (info.max_rx_queues < 1 || info.max_tx_queues < 1) {
        return native_failure(
            "port capability validation",
            std::format("{} does not provide one RX and one TX queue", port.identity)
        );
    }
    if (kFrameMtu < info.min_mtu || (info.max_mtu != 0 && kFrameMtu > info.max_mtu)) {
        return native_failure(
            "port MTU validation",
            std::format("{} does not support the required {}-byte MTU", port.identity, kFrameMtu)
        );
    }

    // DPDK requires unused rte_eth_conf fields and unions to be zeroed.
    rte_eth_conf port_config {}; // NOLINT(bugprone-invalid-enum-default-initialization)
    port_config.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    port_config.rxmode.mtu = kFrameMtu;
    port_config.rxmode.offloads = 0;
    port_config.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    port_config.txmode.offloads = 0;
    uint16_t nb_rx_queue = 1;
    uint16_t nb_tx_queue = 1;

    result = rte_eth_dev_configure(port.id, nb_rx_queue, nb_tx_queue, &port_config);
    if (result != 0)
        return native_failure("port configuration", port.identity, result_error(result));
    port.configured = true;

    uint16_t actual_mtu = 0;
    result = rte_eth_dev_get_mtu(port.id, &actual_mtu);
    if (result != 0)
        return native_failure("port MTU query", port.identity, result_error(result));
    if (actual_mtu != kFrameMtu) {
        result = rte_eth_dev_set_mtu(port.id, kFrameMtu);
        if (result != 0)
            return native_failure("port MTU configuration", port.identity, result_error(result));
    }

    uint16_t rx_descriptors = kRequestedRxDescriptors;
    uint16_t tx_descriptors = kRequestedTxDescriptors;
    result = rte_eth_dev_adjust_nb_rx_tx_desc(port.id, &rx_descriptors, &tx_descriptors);
    if (result != 0)
        return native_failure("descriptor adjustment", port.identity, result_error(result));
    if (rx_descriptors < kMinimumDescriptors || tx_descriptors < kMinimumDescriptors) {
        return native_failure(
            "descriptor validation",
            std::format(
                "{} adjusted descriptors below {} (RX={}, TX={})",
                port.identity,
                kMinimumDescriptors,
                rx_descriptors,
                tx_descriptors
            )
        );
    }
    port.descriptors = { .rx = rx_descriptors, .tx = tx_descriptors };
    return {};
}

std::expected<void, DpdkNativeError>
setup_queues(ProductionDpdkNativeSession::Resources::Port& port, rte_mempool* packet_pool, int fallback_socket) {
    rte_eth_dev_info info {};
    int result = rte_eth_dev_info_get(port.id, &info);
    if (result != 0)
        return native_failure("queue capability query", port.identity, result_error(result));

    const int port_socket = rte_eth_dev_socket_id(port.id);
    const auto queue_socket = static_cast<unsigned>(port_socket >= 0 ? port_socket : fallback_socket);
    rte_eth_rxconf rx_config = info.default_rxconf;
    rx_config.offloads = 0;
    result = rte_eth_rx_queue_setup(port.id, kQueueId, port.descriptors.rx, queue_socket, &rx_config, packet_pool);
    if (result != 0)
        return native_failure("RX queue setup", port.identity, result_error(result));

    rte_eth_txconf tx_config = info.default_txconf;
    tx_config.offloads = 0;
    result = rte_eth_tx_queue_setup(port.id, kQueueId, port.descriptors.tx, queue_socket, &tx_config);
    if (result != 0)
        return native_failure("TX queue setup", port.identity, result_error(result));
    return {};
}

std::expected<void, DpdkNativeError> start_port(ProductionDpdkNativeSession::Resources::Port& port) {
    int result = rte_eth_dev_start(port.id);
    if (result != 0)
        return native_failure("port start", port.identity, result_error(result));
    port.started = true;

    result = rte_eth_promiscuous_enable(port.id);
    if (result != 0)
        return native_failure("promiscuous-mode enable", port.identity, result_error(result));
    port.promiscuous = true;

    result = rte_eth_promiscuous_get(port.id);
    if (result < 0)
        return native_failure("promiscuous-mode query", port.identity, result_error(result));
    if (result == 0)
        return native_failure("promiscuous-mode verification", port.identity);
    return {};
}

void log_link_state(const ProductionDpdkNativeSession::Resources::Port& port) {
    rte_eth_link link {};
    const int result = rte_eth_link_get_nowait(port.id, &link);
    if (result != 0) {
        spdlog::warn("DPDK port {} link query failed: {}", port.identity, result_error(result).message());
        return;
    }
    if (link.link_status == RTE_ETH_LINK_UP) {
        spdlog::info(
            "DPDK port {} link is up (speed={} Mbps, duplex={})",
            port.identity,
            link.link_speed,
            link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "full" : "half"
        );
    } else {
        spdlog::warn("DPDK port {} link is down; startup continues", port.identity);
    }
}

} // namespace

ProductionDpdkNativeSession::ProductionDpdkNativeSession(): resources_(std::make_unique<Resources>()) {}

ProductionDpdkNativeSession::~ProductionDpdkNativeSession() {
    [[maybe_unused]] auto result = release();
}

std::expected<void, DpdkNativeError> ProductionDpdkNativeSession::start(std::span<const std::string> eal_arguments) {
    if (resources_->eal_initialized || resources_->eal_cleanup_attempted)
        return native_failure("EAL initialization", "a DPDK Session is single-use");

    std::vector<std::string> arguments;
    arguments.reserve(eal_arguments.size() + 1);
    arguments.emplace_back("shinku");
    arguments.insert(arguments.end(), eal_arguments.begin(), eal_arguments.end());

    std::vector<char*> argv;
    argv.reserve(arguments.size());
    for (std::string& argument: arguments)
        argv.push_back(argument.data());

    rte_errno = 0;
    const int eal_result = rte_eal_init(static_cast<int>(argv.size()), argv.data());
    if (eal_result < 0)
        return native_failure("EAL initialization", "unable to initialize DPDK", dpdk_errno());
    resources_->eal_initialized = true;

    const auto expected_parsed = static_cast<int>(eal_arguments.size());
    if (eal_result != expected_parsed) {
        return native_failure(
            "EAL argument parsing",
            std::format("DPDK consumed {} of {} EAL arguments", eal_result, expected_parsed)
        );
    }

    const uint16_t port_count = rte_eth_dev_count_avail();
    if (port_count != kRequiredPortCount) {
        return native_failure(
            "port discovery",
            std::format("expected exactly {} DPDK ports, found {}", kRequiredPortCount, port_count)
        );
    }

    resources_->main_socket = static_cast<int>(rte_socket_id());
    resources_->client.id = kClientPortId;
    resources_->client.identity = "client Port ID 0";
    resources_->service.id = kServicePortId;
    resources_->service.identity = "service Port ID 1";

    if (auto result = configure_port(resources_->client); !result)
        return result;
    if (auto result = configure_port(resources_->service); !result)
        return result;

    const std::array descriptors { resources_->client.descriptors, resources_->service.descriptors };
    rte_errno = 0;
    resources_->packet_pool = rte_pktmbuf_pool_create(
        "shinku-packets",
        packet_pool_capacity(descriptors),
        kMempoolCacheSize,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        resources_->main_socket
    );
    if (resources_->packet_pool == nullptr)
        return native_failure("packet-pool creation", "shinku-packets", dpdk_errno());

    if (auto result = setup_queues(resources_->client, resources_->packet_pool, resources_->main_socket); !result)
        return result;
    if (auto result = setup_queues(resources_->service, resources_->packet_pool, resources_->main_socket); !result)
        return result;
    if (auto result = start_port(resources_->client); !result)
        return result;
    if (auto result = start_port(resources_->service); !result)
        return result;

    log_link_state(resources_->client);
    log_link_state(resources_->service);
    return {};
}

uint16_t ProductionDpdkNativeSession::receive(PortSide side, rte_mbuf** packets, uint16_t capacity) noexcept {
    return rte_eth_rx_burst(resources_->port(side).id, kQueueId, packets, capacity);
}

uint16_t ProductionDpdkNativeSession::transmit(PortSide side, rte_mbuf** packets, uint16_t count) noexcept {
    return rte_eth_tx_burst(resources_->port(side).id, kQueueId, packets, count);
}

void ProductionDpdkNativeSession::free_packet(rte_mbuf* packet) noexcept {
    rte_pktmbuf_free(packet);
}

std::string_view ProductionDpdkNativeSession::port_identity(PortSide side) const noexcept {
    return resources_->port(side).identity;
}

std::expected<void, DpdkNativeError> ProductionDpdkNativeSession::release() {
    if (resources_->eal_cleanup_attempted) {
        if (resources_->terminal_cleanup_error.has_value())
            return std::unexpected(*resources_->terminal_cleanup_error);
        return {};
    }
    if (!resources_->eal_initialized)
        return {};

    std::optional<DpdkNativeError> first_error;
    const auto record = [&first_error](DpdkNativeError error) {
        if (!first_error.has_value())
            first_error = std::move(error);
    };
    const auto release_port = [&](Resources::Port& port) {
        if (!port.configured)
            return;

        if (port.promiscuous) {
            const int result = rte_eth_promiscuous_disable(port.id);
            if (result != 0 && result != -ENOTSUP) {
                record(
                    DpdkNativeError {
                        .operation = "promiscuous-mode disable",
                        .detail = port.identity,
                        .cause = result_error(result),
                    }
                );
                return;
            }
            port.promiscuous = false;
        }

        if (port.started) {
            const int result = rte_eth_dev_stop(port.id);
            if (result != 0) {
                record(
                    DpdkNativeError {
                        .operation = "port stop",
                        .detail = port.identity,
                        .cause = result_error(result),
                    }
                );
                return;
            }
            port.started = false;
        }

        const int result = rte_eth_dev_close(port.id);
        if (result != 0) {
            record(
                DpdkNativeError {
                    .operation = "port close",
                    .detail = port.identity,
                    .cause = result_error(result),
                }
            );
            return;
        }
        port.configured = false;
    };

    release_port(resources_->service);
    release_port(resources_->client);

    if (!resources_->client.configured && !resources_->service.configured && resources_->packet_pool != nullptr) {
        rte_mempool_free(resources_->packet_pool);
        resources_->packet_pool = nullptr;
    }

    if (resources_->client.configured || resources_->service.configured || resources_->packet_pool != nullptr) {
        assert(first_error.has_value());
        return std::unexpected(*first_error);
    }

    resources_->eal_cleanup_attempted = true;
    const int cleanup_result = rte_eal_cleanup();
    resources_->eal_initialized = false;
    if (cleanup_result != 0) {
        resources_->terminal_cleanup_error = DpdkNativeError {
            .operation = "EAL cleanup",
            .detail = "terminal cleanup failed",
            .cause = result_error(cleanup_result),
        };
        return std::unexpected(*resources_->terminal_cleanup_error);
    }
    return {};
}

} // namespace shinku::backend::dpdk

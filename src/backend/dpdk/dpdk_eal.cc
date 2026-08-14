// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_eal.h"

#include "backend/dpdk/dpdk_error.h"

#include <cassert>
#include <cstdint>
#include <expected>
#include <format>
#include <optional>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace shinku::backend::dpdk {
namespace {

constexpr uint16_t kRequiredPortCount = 2;

std::optional<std::error_code> dpdk_errno() noexcept {
    if (rte_errno == 0)
        return std::nullopt;
    return std::error_code(rte_errno, std::generic_category());
}

std::error_code result_error(int result) noexcept {
    return { -result, std::generic_category() };
}

std::unexpected<DpdkError>
failure(std::string operation, std::string detail, std::optional<std::error_code> cause = std::nullopt) {
    return std::unexpected(
        DpdkError {
            .operation = std::move(operation),
            .detail = std::move(detail),
            .cause = cause,
        }
    );
}

} // namespace

ProductionDpdkEal::~ProductionDpdkEal() {
    auto _ = close();
}

std::expected<void, DpdkError> ProductionDpdkEal::initialize(std::span<const std::string> eal_arguments) {
    if (initialized_ || cleanup_attempted_)
        return failure("EAL initialization", "a DPDK EAL instance is single-use");

    std::vector<std::string> arguments;
    arguments.reserve(eal_arguments.size() + 1);
    arguments.emplace_back("shinku");
    arguments.insert(arguments.end(), eal_arguments.begin(), eal_arguments.end());

    std::vector<char*> argv;
    argv.reserve(arguments.size());
    for (std::string& argument: arguments)
        argv.push_back(argument.data());

    rte_errno = 0;
    const int result = rte_eal_init(static_cast<int>(argv.size()), argv.data());
    if (result < 0)
        return failure("EAL initialization", "unable to initialize DPDK", dpdk_errno());
    initialized_ = true;

    const auto expected_parsed = static_cast<int>(eal_arguments.size());
    if (result != expected_parsed) {
        return failure(
            "EAL argument parsing",
            std::format("DPDK consumed {} of {} EAL arguments", result, expected_parsed)
        );
    }

    const uint16_t port_count = rte_eth_dev_count_avail();
    if (port_count != kRequiredPortCount) {
        return failure(
            "port discovery",
            std::format("expected exactly {} DPDK ports, found {}", kRequiredPortCount, port_count)
        );
    }

    main_socket_id_ = static_cast<int>(rte_socket_id());
    return {};
}

int ProductionDpdkEal::main_socket_id() const noexcept {
    assert(initialized_);
    return main_socket_id_;
}

std::expected<void, DpdkError> ProductionDpdkEal::close() {
    if (cleanup_attempted_) {
        if (terminal_cleanup_error_)
            return std::unexpected(*terminal_cleanup_error_);
        return {};
    }
    if (!initialized_)
        return {};
    if (owned_ports_ != 0 || owns_packet_pool_) {
        return failure(
            "EAL cleanup",
            std::format("{} DPDK port resource(s) and packet_pool={} remain owned", owned_ports_, owns_packet_pool_),
            std::make_error_code(std::errc::device_or_resource_busy)
        );
    }

    cleanup_attempted_ = true;
    const int result = rte_eal_cleanup();
    initialized_ = false;
    if (result != 0) {
        terminal_cleanup_error_ = DpdkError {
            .operation = "EAL cleanup",
            .detail = "terminal cleanup failed",
            .cause = result_error(result),
        };
        return std::unexpected(*terminal_cleanup_error_);
    }
    return {};
}

void ProductionDpdkEal::acquire_port() noexcept {
    ++owned_ports_;
}

void ProductionDpdkEal::release_port() noexcept {
    assert(owned_ports_ != 0);
    --owned_ports_;
}

void ProductionDpdkEal::acquire_packet_pool() noexcept {
    assert(!owns_packet_pool_);
    owns_packet_pool_ = true;
}

void ProductionDpdkEal::release_packet_pool() noexcept {
    assert(owns_packet_pool_);
    owns_packet_pool_ = false;
}

bool ProductionDpdkEal::has_ports() const noexcept {
    return owned_ports_ != 0;
}

} // namespace shinku::backend::dpdk

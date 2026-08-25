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

/// Exactly two ports (client and service) are required for the forwarding roles.
constexpr uint16_t kRequiredPortCount = 2;

/// Build a std::error_code from the current rte_errno, or empty when it is zero.
std::optional<std::error_code> dpdk_errno() noexcept {
    if (rte_errno == 0)
        return std::nullopt;
    return std::error_code(rte_errno, std::generic_category());
}

/// Convert a negative DPDK return value (a negated errno) into a std::error_code.
std::error_code result_error(int result) noexcept {
    return { -result, std::generic_category() };
}

/// Build an unexpected @ref DpdkError describing a failed DPDK operation.
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

/// Destructor attempts the terminal EAL cleanup so resources are released on unwind.
ProductionDpdkEal::~ProductionDpdkEal() {
    auto _ = close();
}

/**
 * @brief Initialize DPDK EAL and verify the fixed two-port topology.
 *
 * Prepends the program name to the supplied arguments, calls @c rte_eal_init,
 * and then checks that exactly the supplied number of arguments was consumed
 * and that exactly `kRequiredPortCount` ports are available. The EAL is
 * single-use: a second call, or a call after cleanup, fails.
 */
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

/// @return The main socket id captured at initialization; requires a successful @ref initialize.
int ProductionDpdkEal::main_socket_id() const noexcept {
    assert(initialized_);
    return main_socket_id_;
}

/**
 * @brief Shut down the EAL, refusing while owned resources remain.
 *
 * Idempotent: the first call performs the cleanup and records any terminal
 * error, later calls replay that result. If ports or the packet pool are still
 * owned, cleanup is refused so dependent objects cannot be left dangling.
 */
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

/// Record that a port now owns an ethdev resource owned by this EAL.
void ProductionDpdkEal::acquire_port() noexcept {
    ++owned_ports_;
}

/// Record that a port released its ethdev resource.
void ProductionDpdkEal::release_port() noexcept {
    assert(owned_ports_ != 0);
    --owned_ports_;
}

/// Record that a packet pool now owns the mempool owned by this EAL.
void ProductionDpdkEal::acquire_packet_pool() noexcept {
    assert(!owns_packet_pool_);
    owns_packet_pool_ = true;
}

/// Record that the packet pool released the mempool.
void ProductionDpdkEal::release_packet_pool() noexcept {
    assert(owns_packet_pool_);
    owns_packet_pool_ = false;
}

/// @return True while at least one port still owns an ethdev resource.
bool ProductionDpdkEal::has_ports() const noexcept {
    return owned_ports_ != 0;
}

} // namespace shinku::backend::dpdk

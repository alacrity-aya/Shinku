// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_error.h"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

namespace shinku::backend::dpdk {

class ProductionDpdkPacketPool;
class ProductionDpdkPort;

/**
 * @brief Abstract DPDK EAL (Environment Abstraction Layer) owner.
 *
 * The EAL owns DPDK process-wide state: it initializes the runtime, tracks the
 * main NUMA socket, and coordinates cleanup ordering across ports and the packet
 * pool so resources are released in the correct order on shutdown.
 */
class DpdkEal {
public:
    virtual ~DpdkEal() = default;

    DpdkEal(const DpdkEal&) = delete;
    DpdkEal& operator=(const DpdkEal&) = delete;
    DpdkEal(DpdkEal&&) = delete;
    DpdkEal& operator=(DpdkEal&&) = delete;

    /**
     * @brief Initialize the EAL with the supplied arguments.
     * @param arguments EAL arguments (typically forwarded after `--` on the CLI).
     * @return Void on success, or a @ref DpdkError on failure.
     */
    [[nodiscard]] virtual std::expected<void, DpdkError> initialize(std::span<const std::string> arguments) = 0;
    /// @return The main NUMA socket id, or -1 before initialization.
    [[nodiscard]] virtual int main_socket_id() const noexcept = 0;
    /// @brief Release all EAL-owned resources.
    [[nodiscard]] virtual std::expected<void, DpdkError> close() = 0;

protected:
    DpdkEal() = default;
};

/**
 * @brief Production @ref DpdkEal backed by a real DPDK runtime.
 *
 * Tracks port and packet-pool ownership counts so the EAL is only torn down
 * once every port and pool that registered with it has released its claim.
 */
class ProductionDpdkEal final: public DpdkEal {
public:
    ProductionDpdkEal() = default;
    ~ProductionDpdkEal() override;

    [[nodiscard]] std::expected<void, DpdkError> initialize(std::span<const std::string> arguments) override;
    [[nodiscard]] int main_socket_id() const noexcept override;
    [[nodiscard]] std::expected<void, DpdkError> close() override;

private:
    friend class ProductionDpdkPacketPool;
    friend class ProductionDpdkPort;

    /// @brief Register a port with the EAL for cleanup ordering.
    void acquire_port() noexcept;
    /// @brief Release a port's cleanup claim.
    void release_port() noexcept;
    /// @brief Register the packet pool with the EAL for cleanup ordering.
    void acquire_packet_pool() noexcept;
    /// @brief Release the packet pool's cleanup claim.
    void release_packet_pool() noexcept;
    /// @return True if any ports are still registered with this EAL.
    [[nodiscard]] bool has_ports() const noexcept;

    bool initialized_ = false; ///< True once @ref initialize has succeeded.
    bool cleanup_attempted_ = false; ///< True once @ref close has been attempted.
    uint16_t owned_ports_ = 0; ///< Number of ports still registered for cleanup.
    bool owns_packet_pool_ = false; ///< True if the packet pool still registered for cleanup.
    int main_socket_id_ = -1; ///< Main NUMA socket id, or -1 before initialization.
    std::optional<DpdkError> terminal_cleanup_error_; ///< Error captured during final cleanup, if any.
};

} // namespace shinku::backend::dpdk

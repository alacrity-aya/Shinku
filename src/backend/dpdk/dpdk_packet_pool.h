// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_error.h"

#include <array>
#include <cstdint>
#include <expected>

struct rte_mempool;

namespace shinku::backend::dpdk {

class ProductionDpdkEal;
class ProductionDpdkPort;

/// RX/TX descriptor counts requested for a single port direction.
struct DpdkDescriptorCounts {
    uint16_t rx; ///< Number of receive descriptors.
    uint16_t tx; ///< Number of transmit descriptors.
};

/**
 * @brief Abstract DPDK packet (mbuf) memory pool.
 *
 * Owns (or borrows) the rte_mempool from which packet buffers are allocated
 * for RX/TX on the configured ports. Concrete implementations may own the
 * pool or share one owned by the EAL.
 */
class DpdkPacketPool {
public:
    virtual ~DpdkPacketPool() = default;

    DpdkPacketPool(const DpdkPacketPool&) = delete;
    DpdkPacketPool& operator=(const DpdkPacketPool&) = delete;
    DpdkPacketPool(DpdkPacketPool&&) = delete;
    DpdkPacketPool& operator=(DpdkPacketPool&&) = delete;

    /**
     * @brief Create the mempool sized for the two ports' descriptor counts.
     * @param descriptors Per-port RX/TX descriptor counts (index 0 = client, 1 = service).
     * @param socket_id NUMA socket to allocate memory on.
     * @return Void on success, or a @ref DpdkError on failure.
     */
    [[nodiscard]] virtual std::expected<void, DpdkError>
    create(const std::array<DpdkDescriptorCounts, 2>& descriptors, int socket_id) = 0;
    /// @return True if this pool owns the underlying mempool resources.
    [[nodiscard]] virtual bool owns_resources() const noexcept = 0;
    /// @brief Release the mempool if owned.
    [[nodiscard]] virtual std::expected<void, DpdkError> close() = 0;

protected:
    DpdkPacketPool() = default;
};

/**
 * @brief Production @ref DpdkPacketPool backed by a real rte_mempool.
 *
 * Registers pool ownership with the owning @ref ProductionDpdkEal so cleanup
 * ordering across EAL, ports, and the pool is coordinated.
 */
class ProductionDpdkPacketPool final: public DpdkPacketPool {
public:
    /// @brief Construct a pool associated with @p eal for ownership tracking.
    explicit ProductionDpdkPacketPool(ProductionDpdkEal& eal) noexcept;
    ~ProductionDpdkPacketPool() override;

    [[nodiscard]] std::expected<void, DpdkError>
    create(const std::array<DpdkDescriptorCounts, 2>& descriptors, int socket_id) override;
    [[nodiscard]] bool owns_resources() const noexcept override;
    [[nodiscard]] std::expected<void, DpdkError> close() override;

private:
    friend class ProductionDpdkPort;

    /// @return The underlying rte_mempool; valid only after a successful @ref create.
    [[nodiscard]] rte_mempool& native_pool() const noexcept;

    ProductionDpdkEal& eal_; ///< Owning EAL, for coordinated cleanup.
    rte_mempool* pool_ = nullptr; ///< The DPDK mempool, or null before/after @ref create.
};

} // namespace shinku::backend::dpdk

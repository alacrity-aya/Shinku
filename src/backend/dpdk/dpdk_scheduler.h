// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_packet_path.h"

#include <expected>

namespace shinku::backend::dpdk {

/**
 * @brief Cooperative scheduler that drives the four DPDK poll tasks per lcore.
 *
 * On each @ref run_quantum the scheduler yields control to the client, service,
 * cache, and pending poll tasks in turn, implementing single-lcore cooperative
 * forwarding without preemption.
 */
class DpdkCooperativeScheduler {
public:
    /// @brief Construct a scheduler over the four poll tasks.
    /// @param client Poll task for the client-facing port.
    /// @param service Poll task for the service-facing port.
    /// @param cache Poll task for cache cleanup.
    /// @param pending Poll task for pending-query cleanup.
    DpdkCooperativeScheduler(
        DpdkPollTask& client,
        DpdkPollTask& service,
        DpdkPollTask& cache,
        DpdkPollTask& pending
    ) noexcept;

    /// @brief Run one scheduling quantum over all four poll tasks.
    /// @return Void on success, or a @ref BackendError if any task failed.
    [[nodiscard]] std::expected<void, BackendError> run_quantum();

private:
    DpdkPollTask& client_; ///< Client-facing poll task.
    DpdkPollTask& service_; ///< Service-facing poll task.
    DpdkPollTask& cache_; ///< Cache-cleanup poll task.
    DpdkPollTask& pending_; ///< Pending-query cleanup poll task.
};

} // namespace shinku::backend::dpdk

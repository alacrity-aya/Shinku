// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend_error.h"

#include <cstdint>
#include <expected>

namespace shinku::backend {

class BackendRunner;

/// Lifecycle states a @ref Backend may occupy.
enum class BackendState : uint8_t {
    Created, ///< Constructed but not yet probed or started.
    Running, ///< Started and being polled in the run loop.
    Stopped, ///< Cleanly stopped after a normal shutdown.
    Failed, ///< Stopped due to a backend or run-loop error.
};

/**
 * @brief Abstract lifecycle interface for a packet-processing backend.
 *
 * Concrete backends (eBPF, DPDK) implement the probe/start/poll/stop phases
 * so the @ref BackendRunner can drive them uniformly. All methods return a
 * @ref BackendError on failure rather than throwing.
 *
 * The Backend is non-copyable and non-movable: it owns live kernel/hardware
 * resources that cannot be transferred.
 */
class Backend {
public:
    friend class BackendRunner;

    Backend(const Backend&) = delete;
    Backend& operator=(const Backend&) = delete;
    Backend(Backend&&) = delete;
    Backend& operator=(Backend&&) = delete;
    virtual ~Backend() = default;

protected:
    Backend() = default;

    /// @brief Probe for required capabilities/resources before starting.
    [[nodiscard]] virtual std::expected<void, BackendError> probe() = 0;
    /// @brief Start the backend's packet-processing loops.
    [[nodiscard]] virtual std::expected<void, BackendError> start() = 0;
    /// @brief Drive one iteration of the backend's polling loop.
    [[nodiscard]] virtual std::expected<void, BackendError> poll() = 0;
    /// @brief Stop the backend and release its processing resources.
    [[nodiscard]] virtual std::expected<void, BackendError> stop() = 0;
};

} // namespace shinku::backend

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend.h"
#include "backend_error.h"
#include "stop_condition.h"

#include <expected>
#include <memory>

namespace shinku::backend {

/// @brief Report produced when a @ref BackendRunner completes a run.
struct ShutdownReport {
    StopRequest accepted_stop; ///< The stop request that terminated the run.
};

/**
 * @brief Owns a @ref Backend and drives its run loop until shutdown.
 *
 * The runner is the single owner of a Backend instance: it probes, starts,
 * polls until a stop is requested, and then stops the backend, transitioning
 * the @ref BackendState accordingly. It is non-copyable and non-movable
 * because the Backend it owns is neither.
 */
class BackendRunner final {
public:
    /// @brief Construct a runner that owns @p backend.
    explicit BackendRunner(std::unique_ptr<Backend> backend) noexcept;
    ~BackendRunner() noexcept;

    BackendRunner(const BackendRunner&) = delete;
    BackendRunner& operator=(const BackendRunner&) = delete;
    BackendRunner(BackendRunner&&) = delete;
    BackendRunner& operator=(BackendRunner&&) = delete;

    /**
     * @brief Run the backend until @p stop_condition signals a stop.
     *
     * Probes and starts the backend, then repeatedly polls it while checking
     * the stop condition. On a stop request or a poll failure, the backend is
     * stopped and the final state is recorded.
     *
     * @param stop_condition Polled each iteration to detect a shutdown request.
     * @return The shutdown report, or a @ref BackendError on failure.
     */
    [[nodiscard]] std::expected<ShutdownReport, BackendError> run(StopCondition& stop_condition);
    /// @return The current backend state.
    [[nodiscard]] BackendState state() const noexcept;

private:
    /// @brief Stop the owned backend and update @ref state_.
    [[nodiscard]] std::expected<void, BackendError> stop_backend();

    std::unique_ptr<Backend> backend_; ///< The owned backend instance.
    BackendState state_ = BackendState::Created; ///< Current lifecycle state.
    bool backend_active_ = false; ///< True once the backend has been started.
};

} // namespace shinku::backend

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/stop_condition.h"
#include "process_control_error.h"

#include <expected>

namespace shinku::process_control {

class ProcessControlTestAccess;

/**
 * @brief Process-wide signal handling and shutdown request source.
 *
 * ProcessControl is a singleton that installs signal handlers for SIGINT and
 * SIGTERM, records a shutdown request when one is delivered, and exposes the
 * request to the @ref backend::BackendRunner via the @ref backend::StopCondition
 * interface. It is non-copyable and non-movable because it owns process-global
 * signal disposition.
 */
class ProcessControl final: public backend::StopCondition {
public:
    /// @return The process-wide ProcessControl instance.
    static ProcessControl& instance() noexcept;

    ProcessControl(const ProcessControl&) = delete;
    ProcessControl& operator=(const ProcessControl&) = delete;
    ProcessControl(ProcessControl&&) = delete;
    ProcessControl& operator=(ProcessControl&&) = delete;

    /// @brief Mark a shutdown request from any thread (signal-safe context).
    static void request_shutdown() noexcept;
    /// @return True if a shutdown has been requested since the last reset.
    [[nodiscard]] static bool shutdown_requested() noexcept;
    /**
     * @brief Install the SIGINT/SIGTERM handlers that drive shutdown.
     * @return Void on success, or a @ref ProcessControlError if installation failed.
     */
    static std::expected<void, ProcessControlError> install_signal_handlers();

    /**
     * @brief Poll for a pending shutdown request.
     * @return A @ref backend::StopRequest if shutdown has been requested, otherwise empty.
     */
    [[nodiscard]] std::optional<backend::StopRequest> poll() noexcept override;

private:
    friend class ProcessControlTestAccess;

    ProcessControl() = default;
    ~ProcessControl() override = default;

    /// @brief Reset the shutdown state; intended for use by tests only.
    static void reset_for_tests() noexcept;
};

} // namespace shinku::process_control

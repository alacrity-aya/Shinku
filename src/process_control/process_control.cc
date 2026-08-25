// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "process_control/process_control.h"

#include "backend/stop_condition.h"
#include "process_control/process_control_error.h"

#include <cerrno>
#include <csignal>
#include <expected>
#include <format>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

namespace shinku::process_control {
namespace {

/// Set by a signal handler when shutdown was requested; the only async-safe shared flag.
volatile sig_atomic_t shutdown_requested_flag = 0;
/// True once SIGINT/SIGTERM handlers have been installed successfully.
bool signal_handlers_installed = false;

/// Async-signal-safe handler that records the shutdown request.
void handle_shutdown_signal(int _) noexcept {
    shutdown_requested_flag = 1;
}

/// Build an unexpected @ref ProcessControlError describing a failed sigaction install.
std::unexpected<ProcessControlError> signal_install_error(std::string_view signal_name, std::error_code error) {
    auto message = std::format("sigaction({}) failed: {}", signal_name, error.message());

    return std::unexpected(
        ProcessControlError {
            .code = ProcessControlErrorCode::SignalInstallFailed,
            .error = error,
            .message = std::move(message),
        }
    );
}

/// Install @ref handle_shutdown_signal for one signal, reporting failures with its name.
std::expected<void, ProcessControlError> install_handler(int signal_number, std::string_view signal_name) {
    struct sigaction action {};
    action.sa_handler = handle_shutdown_signal;
    sigemptyset(&action.sa_mask);

    if (sigaction(signal_number, &action, nullptr) != 0)
        return signal_install_error(signal_name, std::error_code(errno, std::generic_category()));

    return {};
}

} // namespace

/// @return The process-wide singleton @ref ProcessControl instance.
ProcessControl& ProcessControl::instance() noexcept {
    static ProcessControl control;
    return control;
}

/// Record that shutdown was requested; safe to call from signal context.
void ProcessControl::request_shutdown() noexcept {
    shutdown_requested_flag = 1;
}

/// @return True once shutdown has been requested.
bool ProcessControl::shutdown_requested() noexcept {
    return shutdown_requested_flag != 0;
}

/// @return A @ref backend::StopRequest when shutdown was requested, otherwise nullopt.
std::optional<backend::StopRequest> ProcessControl::poll() noexcept {
    if (!shutdown_requested())
        return std::nullopt;

    return backend::StopRequest { .reason = backend::StopReason::Signal };
}

/// Install SIGINT and SIGTERM handlers once; later calls are idempotent.
std::expected<void, ProcessControlError> ProcessControl::install_signal_handlers() {
    if (signal_handlers_installed)
        return {};

    auto sigint = install_handler(SIGINT, "SIGINT");
    if (!sigint)
        return std::unexpected(sigint.error());

    auto sigterm = install_handler(SIGTERM, "SIGTERM");
    if (!sigterm)
        return std::unexpected(sigterm.error());

    signal_handlers_installed = true;
    return {};
}

/// Clear the shutdown flag so tests can start from a clean process state.
void ProcessControl::reset_for_tests() noexcept {
    shutdown_requested_flag = 0;
}

} // namespace shinku::process_control

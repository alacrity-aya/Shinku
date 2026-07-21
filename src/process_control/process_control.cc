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

volatile sig_atomic_t shutdown_requested_flag = 0;
bool signal_handlers_installed = false;

void handle_shutdown_signal([[maybe_unused]] int signal_number) noexcept {
    shutdown_requested_flag = 1;
}

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

std::expected<void, ProcessControlError> install_handler(int signal_number, std::string_view signal_name) {
    struct sigaction action {};
    action.sa_handler = handle_shutdown_signal;
    sigemptyset(&action.sa_mask);

    if (sigaction(signal_number, &action, nullptr) != 0)
        return signal_install_error(signal_name, std::error_code(errno, std::generic_category()));

    return {};
}

} // namespace

ProcessControl& ProcessControl::instance() noexcept {
    static ProcessControl control;
    return control;
}

void ProcessControl::request_shutdown() noexcept {
    shutdown_requested_flag = 1;
}

bool ProcessControl::shutdown_requested() noexcept {
    return shutdown_requested_flag != 0;
}

std::optional<backend::StopRequest> ProcessControl::poll() noexcept {
    if (!shutdown_requested())
        return std::nullopt;

    return backend::StopRequest { .reason = backend::StopReason::Signal };
}

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

void ProcessControl::reset_for_tests() noexcept {
    shutdown_requested_flag = 0;
}

} // namespace shinku::process_control

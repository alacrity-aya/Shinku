// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "process_control_error.h"

#include <expected>
#include <string_view>
#include <system_error>

namespace shinku::process_control {

class ProcessControlTestAccess;

class ProcessControl final {
public:
    static ProcessControl& instance() noexcept;

    ProcessControl(const ProcessControl&) = delete;
    ProcessControl& operator=(const ProcessControl&) = delete;
    ProcessControl(ProcessControl&&) = delete;
    ProcessControl& operator=(ProcessControl&&) = delete;

    static void request_shutdown() noexcept;
    [[nodiscard]] static bool shutdown_requested() noexcept;
    static std::expected<void, ProcessControlError> install_signal_handlers();

private:
    friend class ProcessControlTestAccess;

    ProcessControl() = default;
    ~ProcessControl() = default;

    static void handle_shutdown_signal(int signal_number) noexcept;
    static std::expected<void, ProcessControlError> install_handler(int signal_number, std::string_view signal_name);
    static std::unexpected<ProcessControlError>
    signal_install_error(std::string_view signal_name, std::error_code error);

    static void reset_for_tests() noexcept;
};

} // namespace shinku::process_control

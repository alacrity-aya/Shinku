// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <string>
#include <system_error>

namespace shinku::process_control {

enum class ProcessControlErrorCode : uint8_t {
    SignalInstallFailed,
};

struct ProcessControlError {
    ProcessControlErrorCode code;
    std::error_code error;
    std::string message;
};

} // namespace shinku::process_control

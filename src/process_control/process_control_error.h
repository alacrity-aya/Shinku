// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <string>
#include <system_error>

namespace shinku::process_control {

/// Failure codes returned by @ref ProcessControl operations.
enum class ProcessControlErrorCode : uint8_t {
    SignalInstallFailed, ///< A signal handler could not be installed.
};

/// Error returned by @ref ProcessControl, carrying the underlying system error.
struct ProcessControlError {
    ProcessControlErrorCode code; ///< The failure category.
    std::error_code error; ///< Underlying system error.
    std::string message; ///< Human-readable description of the failure.
};

} // namespace shinku::process_control

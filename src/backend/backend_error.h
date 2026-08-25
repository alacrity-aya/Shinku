// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <system_error>

namespace shinku::backend {

/// Failure categories returned by @ref Backend and @ref BackendRunner operations.
enum class BackendErrorCode : uint8_t {
    InvalidState, ///< The operation was invoked from a state that does not permit it.
    WrongConfig, ///< The supplied configuration is structurally invalid for the backend.
    Unsupported, ///< The host cannot support the requested backend.
    PermissionDenied, ///< The backend requires privileges the process does not hold.
    ProbeFailed, ///< The probe phase could not verify required capabilities.
    StartFailed, ///< The start phase failed after a successful probe.
    PollFailed, ///< A polling iteration failed and aborted the run loop.
    StopFailed, ///< The stop phase failed during shutdown.
};

/// Error returned by backend operations, carrying an optional underlying cause.
struct BackendError {
    BackendErrorCode code; ///< The failure category.
    std::string message; ///< Human-readable description of the failure.
    std::optional<std::error_code> cause; ///< Underlying system error, if any.
};

} // namespace shinku::backend

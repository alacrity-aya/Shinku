// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <system_error>

namespace shinku::backend {

enum class BackendErrorCode : uint8_t {
    InvalidState,
    WrongConfig,
    Unsupported,
    PermissionDenied,
    ProbeFailed,
    StartFailed,
    PollFailed,
    StopFailed,
};

struct BackendError {
    BackendErrorCode code;
    std::string message;
    std::optional<std::error_code> cause;
};

} // namespace shinku::backend

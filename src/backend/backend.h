// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend_error.h"

#include <cstdint>
#include <expected>
#include <string>

namespace shinku::backend {

enum class BackendState : uint8_t {
    Created,
    Running,
    Stopped,
    Failed,
};

enum class ProbeStatus : uint8_t {
    Supported,
    Unsupported,
};

struct ProbeResult {
    ProbeStatus status;
    std::string message;
};

enum class PollStatus : uint8_t {
    WorkDone,
    NoWork,
};

class Backend {
public:
    Backend(const Backend&) = delete;
    Backend& operator=(const Backend&) = delete;
    Backend(Backend&&) = delete;
    Backend& operator=(Backend&&) = delete;
    virtual ~Backend() = default;

    [[nodiscard]] virtual std::expected<ProbeResult, BackendError> probe() = 0;
    [[nodiscard]] virtual std::expected<void, BackendError> start() = 0;
    [[nodiscard]] virtual std::expected<PollStatus, BackendError> poll_once() = 0;
    [[nodiscard]] virtual std::expected<void, BackendError> stop() = 0;

protected:
    Backend() = default;
};

} // namespace shinku::backend

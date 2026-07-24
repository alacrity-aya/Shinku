// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend_error.h"

#include <cstdint>
#include <expected>

namespace shinku::backend {

class BackendRunner;

enum class BackendState : uint8_t {
    Created,
    Running,
    Stopped,
    Failed,
};

enum class PollStatus : uint8_t {
    WorkDone,
    NoWork,
};

class Backend {
public:
    friend class BackendRunner;

    Backend(const Backend&) = delete;
    Backend& operator=(const Backend&) = delete;
    Backend(Backend&&) = delete;
    Backend& operator=(Backend&&) = delete;
    virtual ~Backend() = default;

protected:
    Backend() = default;

    [[nodiscard]] virtual std::expected<void, BackendError> probe() = 0;
    [[nodiscard]] virtual std::expected<void, BackendError> start() = 0;
    [[nodiscard]] virtual std::expected<PollStatus, BackendError> poll() = 0;
    [[nodiscard]] virtual std::expected<void, BackendError> stop() = 0;
};

} // namespace shinku::backend

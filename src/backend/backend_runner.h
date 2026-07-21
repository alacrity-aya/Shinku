// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend.h"
#include "backend_error.h"
#include "stop_condition.h"

#include <expected>
#include <memory>

namespace shinku::backend {

struct ShutdownReport {
    StopRequest accepted_stop;
};

class BackendRunner final {
public:
    explicit BackendRunner(std::unique_ptr<Backend> backend) noexcept;
    ~BackendRunner() noexcept;

    BackendRunner(const BackendRunner&) = delete;
    BackendRunner& operator=(const BackendRunner&) = delete;
    BackendRunner(BackendRunner&&) = delete;
    BackendRunner& operator=(BackendRunner&&) = delete;

    [[nodiscard]] std::expected<ShutdownReport, BackendError> run(StopCondition& stop_condition);
    [[nodiscard]] BackendState state() const noexcept;

private:
    [[nodiscard]] std::expected<void, BackendError> stop_backend();

    std::unique_ptr<Backend> backend_;
    BackendState state_ = BackendState::Created;
    bool backend_active_ = false;
};

} // namespace shinku::backend

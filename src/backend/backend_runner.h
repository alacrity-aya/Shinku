// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend.h"
#include "backend_error.h"

#include <expected>
#include <memory>

namespace shinku::backend {

class BackendRunner final {
public:
    explicit BackendRunner(std::unique_ptr<Backend> backend) noexcept;
    ~BackendRunner() noexcept;

    BackendRunner(const BackendRunner&) = delete;
    BackendRunner& operator=(const BackendRunner&) = delete;
    BackendRunner(BackendRunner&&) = delete;
    BackendRunner& operator=(BackendRunner&&) = delete;

    [[nodiscard]] BackendState state() const noexcept;
    [[nodiscard]] std::expected<ProbeResult, BackendError> probe();
    [[nodiscard]] std::expected<void, BackendError> start();
    [[nodiscard]] std::expected<PollStatus, BackendError> poll_once();
    [[nodiscard]] std::expected<void, BackendError> stop();

private:
    std::unique_ptr<Backend> backend_;
    BackendState state_ = BackendState::Created;
};

} // namespace shinku::backend

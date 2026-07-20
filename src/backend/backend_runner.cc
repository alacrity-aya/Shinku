// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_runner.h"

#include <expected>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>

namespace shinku::backend {
namespace {

std::string_view state_name(BackendState state) {
    switch (state) {
        case BackendState::Created:
            return "Created";
        case BackendState::Running:
            return "Running";
        case BackendState::Stopped:
            return "Stopped";
        case BackendState::Failed:
            return "Failed";
    }
    return "Unknown";
}

std::unexpected<BackendError> invalid_state_error(std::string_view operation, BackendState state) {
    auto message = std::format("cannot {} backend while runner is {}", operation, state_name(state));

    return std::unexpected(
        BackendError {
            .code = BackendErrorCode::InvalidState,
            .message = std::move(message),
            .cause = std::nullopt,
        }
    );
}

std::unexpected<BackendError> missing_backend_error(std::string_view operation) {
    auto message = std::format("cannot {} backend: backend object is missing", operation);

    return std::unexpected(
        BackendError {
            .code = BackendErrorCode::InvalidState,
            .message = std::move(message),
            .cause = std::nullopt,
        }
    );
}

BackendError unsupported_start_error(const ProbeResult& probe_result) {
    auto message = probe_result.message.empty() ? std::string("backend unsupported")
                                                : std::format("backend unsupported: {}", probe_result.message);

    return BackendError {
        .code = BackendErrorCode::Unsupported,
        .message = std::move(message),
        .cause = std::nullopt,
    };
}

} // namespace

BackendRunner::BackendRunner(std::unique_ptr<Backend> backend) noexcept: backend_(std::move(backend)) {}

BackendRunner::~BackendRunner() noexcept {
    if (state_ == BackendState::Stopped)
        return;

    auto result = stop();
    if (!result) {
        std::println(stderr, "error: backend stop failed during shutdown: {}", result.error().message);
    }
}

BackendState BackendRunner::state() const noexcept {
    return state_;
}

std::expected<ProbeResult, BackendError> BackendRunner::probe() {
    if (!backend_)
        return missing_backend_error("probe");
    if (state_ != BackendState::Created)
        return invalid_state_error("probe", state_);

    return backend_->probe();
}

std::expected<void, BackendError> BackendRunner::start() {
    if (!backend_)
        return missing_backend_error("start");
    if (state_ != BackendState::Created)
        return invalid_state_error("start", state_);

    auto probe_result = backend_->probe();
    if (!probe_result) {
        state_ = BackendState::Failed;
        return std::unexpected(probe_result.error());
    }

    if (probe_result->status == ProbeStatus::Unsupported) {
        state_ = BackendState::Failed;
        return std::unexpected(unsupported_start_error(*probe_result));
    }

    auto start_result = backend_->start();
    if (!start_result) {
        state_ = BackendState::Failed;
        return std::unexpected(start_result.error());
    }

    state_ = BackendState::Running;
    return {};
}

std::expected<PollStatus, BackendError> BackendRunner::poll_once() {
    if (!backend_)
        return missing_backend_error("poll_once");
    if (state_ != BackendState::Running)
        return invalid_state_error("poll_once", state_);

    auto poll_result = backend_->poll_once();
    if (!poll_result) {
        state_ = BackendState::Failed;
        return std::unexpected(poll_result.error());
    }

    return *poll_result;
}

std::expected<void, BackendError> BackendRunner::stop() {
    if (!backend_)
        return missing_backend_error("stop");
    if (state_ == BackendState::Stopped)
        return {};
    if (state_ == BackendState::Created) {
        state_ = BackendState::Stopped;
        return {};
    }

    auto stop_result = backend_->stop();
    if (!stop_result) {
        state_ = BackendState::Failed;
        return std::unexpected(stop_result.error());
    }

    state_ = BackendState::Stopped;
    return {};
}

} // namespace shinku::backend

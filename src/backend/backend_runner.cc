// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_runner.h"

#include "backend/backend.h"
#include "backend/backend_error.h"
#include "backend/stop_condition.h"

#include <expected>
#include <format>
#include <memory>
#include <optional>
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
    std::unreachable();
}

std::unexpected<BackendError> invalid_state_error(BackendState state) {
    auto message = std::format("cannot run backend while runner is {}", state_name(state));

    return std::unexpected(
        BackendError {
            .code = BackendErrorCode::InvalidState,
            .message = std::move(message),
            .cause = std::nullopt,
        }
    );
}

std::unexpected<BackendError> missing_backend_error() {
    return std::unexpected(
        BackendError {
            .code = BackendErrorCode::InvalidState,
            .message = "cannot run backend: backend object is missing",
            .cause = std::nullopt,
        }
    );
}

std::unexpected<BackendError> stop_failed_error(StopRequest request, const BackendError& error) {
    return std::unexpected(
        BackendError {
            .code = BackendErrorCode::StopFailed,
            .message = std::format(
                "failed to stop backend after {} shutdown request: {}",
                stop_reason_name(request.reason),
                error.message
            ),
            .cause = error.cause,
        }
    );
}

} // namespace

BackendRunner::BackendRunner(std::unique_ptr<Backend> backend) noexcept: backend_(std::move(backend)) {}

BackendRunner::~BackendRunner() noexcept {
    if (backend_active_) {
        auto _ = stop_backend();
    }
}

BackendState BackendRunner::state() const noexcept {
    return state_;
}

std::expected<ShutdownReport, BackendError> BackendRunner::run(StopCondition& stop_condition) {
    if (state_ != BackendState::Created)
        return invalid_state_error(state_);
    if (!backend_) {
        state_ = BackendState::Failed;
        return missing_backend_error();
    }

    if (auto request = stop_condition.poll()) {
        state_ = BackendState::Stopped;
        return ShutdownReport { .accepted_stop = *request };
    }

    auto probe_result = backend_->probe();
    if (!probe_result) {
        state_ = BackendState::Failed;
        return std::unexpected(probe_result.error());
    }

    backend_active_ = true;
    auto start_result = backend_->start();
    if (!start_result) {
        state_ = BackendState::Failed;
        auto _ = stop_backend();
        return std::unexpected(start_result.error());
    }

    state_ = BackendState::Running;

    // main loop
    while (true) {
        if (auto request = stop_condition.poll()) {
            auto stopped = stop_backend();
            if (!stopped) {
                state_ = BackendState::Failed;
                return stop_failed_error(*request, stopped.error());
            }

            state_ = BackendState::Stopped;
            return ShutdownReport { .accepted_stop = *request };
        }

        auto poll_result = backend_->poll();
        if (!poll_result) {
            state_ = BackendState::Failed;
            BackendError original_error = std::move(poll_result.error());
            auto _ = stop_backend(); //TODO: need loggin here
            return std::unexpected(std::move(original_error));
        }
    }
}

std::expected<void, BackendError> BackendRunner::stop_backend() {
    auto stop_result = backend_->stop();
    if (!stop_result)
        return std::unexpected(stop_result.error());

    backend_active_ = false;
    return {};
}

} // namespace shinku::backend

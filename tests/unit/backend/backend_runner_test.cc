// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_runner.h"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using shinku::backend::Backend;
using shinku::backend::BackendError;
using shinku::backend::BackendErrorCode;
using shinku::backend::BackendRunner;
using shinku::backend::BackendState;
using shinku::backend::PollStatus;
using shinku::backend::StopCondition;
using shinku::backend::StopReason;
using shinku::backend::StopRequest;

struct FakeBackendTrace {
    int probe_calls = 0;
    int start_calls = 0;
    int poll_calls = 0;
    int stop_calls = 0;
    std::vector<std::string> calls;
};

BackendError
backend_error(BackendErrorCode code, std::string_view message, std::optional<std::error_code> cause = std::nullopt) {
    return BackendError {
        .code = code,
        .message = std::string(message),
        .cause = cause,
    };
}

class FakeBackend final: public Backend {
public:
    explicit FakeBackend(std::shared_ptr<FakeBackendTrace> trace): trace_(std::move(trace)) {}

    std::expected<void, BackendError> probe_result;
    std::expected<void, BackendError> start_result;
    std::expected<PollStatus, BackendError> poll_result = PollStatus::NoWork;
    std::vector<std::expected<void, BackendError>> stop_results;

    std::expected<void, BackendError> probe() override {
        trace_->probe_calls++;
        trace_->calls.emplace_back("probe");
        return probe_result;
    }

    std::expected<void, BackendError> start() override {
        trace_->start_calls++;
        trace_->calls.emplace_back("start");
        return start_result;
    }

    std::expected<PollStatus, BackendError> poll_once() override {
        trace_->poll_calls++;
        trace_->calls.emplace_back("poll_once");
        return poll_result;
    }

    std::expected<void, BackendError> stop() override {
        trace_->stop_calls++;
        trace_->calls.emplace_back("stop");
        if (next_stop_result_ < stop_results.size())
            return stop_results.at(next_stop_result_++);
        return {};
    }

private:
    std::shared_ptr<FakeBackendTrace> trace_;
    std::size_t next_stop_result_ = 0;
};

class SequencedStopCondition final: public StopCondition {
public:
    explicit SequencedStopCondition(std::vector<std::optional<StopRequest>> results): results_(std::move(results)) {}

    std::optional<StopRequest> poll() noexcept override {
        if (next_result_ < results_.size())
            return results_[next_result_++];
        return StopRequest { .reason = StopReason::Manual };
    }

private:
    std::vector<std::optional<StopRequest>> results_;
    std::size_t next_result_ = 0;
};

struct RunnerFixture {
    std::shared_ptr<FakeBackendTrace> trace = std::make_shared<FakeBackendTrace>();
    FakeBackend* backend = nullptr;
    std::unique_ptr<BackendRunner> runner;

    RunnerFixture() {
        auto fake = std::make_unique<FakeBackend>(trace);
        backend = fake.get();
        runner = std::make_unique<BackendRunner>(std::move(fake));
    }
};

static_assert(noexcept(std::declval<StopCondition&>().poll()));

} // namespace

TEST_CASE("BackendRunner initial state is Created") {
    RunnerFixture fixture;

    CHECK(fixture.runner->state() == BackendState::Created);
    CHECK(fixture.trace->calls.empty());
}

TEST_CASE("BackendRunner accepts a pre-existing stop request without starting") {
    RunnerFixture fixture;
    SequencedStopCondition stop_condition({ StopRequest { .reason = StopReason::Manual } });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE(result.has_value());
    CHECK(result->accepted_stop.reason == StopReason::Manual);
    CHECK(fixture.runner->state() == BackendState::Stopped);
    CHECK(fixture.trace->calls.empty());
}

TEST_CASE("BackendRunner owns probe start poll and stop sequencing") {
    RunnerFixture fixture;
    SequencedStopCondition stop_condition({ std::nullopt, std::nullopt, StopRequest { .reason = StopReason::Signal } });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE(result.has_value());
    CHECK(result->accepted_stop.reason == StopReason::Signal);
    CHECK(fixture.runner->state() == BackendState::Stopped);
    CHECK(fixture.trace->calls == std::vector<std::string> { "probe", "start", "poll_once", "stop" });
}

TEST_CASE("BackendRunner preserves probe failure without starting or stopping") {
    RunnerFixture fixture;
    fixture.backend->probe_result = std::unexpected(backend_error(BackendErrorCode::Unsupported, "missing BPF arena"));
    SequencedStopCondition stop_condition({ std::nullopt });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::Unsupported);
    CHECK(fixture.runner->state() == BackendState::Failed);
    CHECK(fixture.trace->calls == std::vector<std::string> { "probe" });
}

TEST_CASE("BackendRunner cleans up after start failure and does not repeat successful cleanup") {
    auto trace = std::make_shared<FakeBackendTrace>();
    {
        auto fake = std::make_unique<FakeBackend>(trace);
        fake->start_result = std::unexpected(backend_error(BackendErrorCode::StartFailed, "start failed"));
        BackendRunner runner(std::move(fake));
        SequencedStopCondition stop_condition({ std::nullopt });

        auto result = runner.run(stop_condition);

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::StartFailed);
        CHECK(runner.state() == BackendState::Failed);
        CHECK(trace->calls == std::vector<std::string> { "probe", "start", "stop" });
    }

    CHECK(trace->stop_calls == 1);
}

TEST_CASE("BackendRunner preserves start failure and retries failed cleanup in destructor") {
    auto trace = std::make_shared<FakeBackendTrace>();
    {
        auto fake = std::make_unique<FakeBackend>(trace);
        fake->start_result = std::unexpected(backend_error(BackendErrorCode::StartFailed, "start failed"));
        fake->stop_results = {
            std::unexpected(backend_error(BackendErrorCode::StopFailed, "first cleanup failed")),
            {},
        };
        BackendRunner runner(std::move(fake));
        SequencedStopCondition stop_condition({ std::nullopt });

        auto result = runner.run(stop_condition);

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().message == "start failed");
        CHECK(trace->stop_calls == 1);
    }

    CHECK(trace->stop_calls == 2);
}

TEST_CASE("BackendRunner returns the original poll error after successful cleanup") {
    RunnerFixture fixture;
    fixture.backend->poll_result =
        std::unexpected(backend_error(BackendErrorCode::PollFailed, "packet ring poll failed"));
    SequencedStopCondition stop_condition({ std::nullopt, std::nullopt });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::PollFailed);
    CHECK(result.error().message == "packet ring poll failed");
    CHECK(fixture.runner->state() == BackendState::Failed);
    CHECK(fixture.trace->calls == std::vector<std::string> { "probe", "start", "poll_once", "stop" });

    fixture.runner.reset();
    CHECK(fixture.trace->stop_calls == 1);
}

TEST_CASE("BackendRunner reports stop failure with the accepted reason") {
    RunnerFixture fixture;
    const auto cause = std::make_error_code(std::errc::io_error);
    fixture.backend->stop_results = {
        std::unexpected(backend_error(BackendErrorCode::StopFailed, "cleanup failed", cause)),
        {},
    };
    SequencedStopCondition stop_condition({ std::nullopt, StopRequest { .reason = StopReason::Timeout } });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StopFailed);
    CHECK(result.error().message.find("timeout") != std::string::npos);
    CHECK(result.error().message.find("cleanup failed") != std::string::npos);
    CHECK(result.error().cause == cause);
    CHECK(fixture.runner->state() == BackendState::Failed);
}

TEST_CASE("BackendRunner run is single-use") {
    RunnerFixture fixture;
    SequencedStopCondition first_stop({ StopRequest { .reason = StopReason::Manual } });
    REQUIRE(fixture.runner->run(first_stop).has_value());
    SequencedStopCondition second_stop({ StopRequest { .reason = StopReason::Signal } });

    auto second_result = fixture.runner->run(second_stop);

    REQUIRE_FALSE(second_result.has_value());
    CHECK(second_result.error().code == BackendErrorCode::InvalidState);
    CHECK(fixture.runner->state() == BackendState::Stopped);
}

TEST_CASE("BackendRunner rejects a missing backend") {
    BackendRunner runner(nullptr);
    SequencedStopCondition stop_condition({ StopRequest { .reason = StopReason::Manual } });

    auto result = runner.run(stop_condition);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::InvalidState);
    CHECK(runner.state() == BackendState::Failed);
}

TEST_CASE("stop_reason_name provides canonical names") {
    CHECK(shinku::backend::stop_reason_name(StopReason::Signal) == "signal");
    CHECK(shinku::backend::stop_reason_name(StopReason::Manual) == "manual");
    CHECK(shinku::backend::stop_reason_name(StopReason::Timeout) == "timeout");
}

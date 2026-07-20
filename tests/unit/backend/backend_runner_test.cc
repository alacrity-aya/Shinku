// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_runner.h"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

struct FakeBackendTrace {
    int probe_calls = 0;
    int start_calls = 0;
    int poll_calls = 0;
    int stop_calls = 0;
    std::vector<std::string> calls;
};

shinku::backend::BackendError backend_error(shinku::backend::BackendErrorCode code, std::string_view message) {
    return shinku::backend::BackendError {
        .code = code,
        .message = std::string(message),
        .cause = std::nullopt,
    };
}

class FakeBackend final: public shinku::backend::Backend {
public:
    explicit FakeBackend(std::shared_ptr<FakeBackendTrace> trace): trace_(std::move(trace)) {}

    std::expected<shinku::backend::ProbeResult, shinku::backend::BackendError> probe_result =
        shinku::backend::ProbeResult {
            .status = shinku::backend::ProbeStatus::Supported,
            .message = "supported",
        };
    std::expected<void, shinku::backend::BackendError> start_result;
    std::expected<shinku::backend::PollStatus, shinku::backend::BackendError> poll_result =
        shinku::backend::PollStatus::NoWork;
    std::expected<void, shinku::backend::BackendError> stop_result;

    std::expected<shinku::backend::ProbeResult, shinku::backend::BackendError> probe() override {
        trace_->probe_calls++;
        trace_->calls.emplace_back("probe");
        return probe_result;
    }

    std::expected<void, shinku::backend::BackendError> start() override {
        trace_->start_calls++;
        trace_->calls.emplace_back("start");
        return start_result;
    }

    std::expected<shinku::backend::PollStatus, shinku::backend::BackendError> poll_once() override {
        trace_->poll_calls++;
        trace_->calls.emplace_back("poll_once");
        return poll_result;
    }

    std::expected<void, shinku::backend::BackendError> stop() override {
        trace_->stop_calls++;
        trace_->calls.emplace_back("stop");
        return stop_result;
    }

private:
    std::shared_ptr<FakeBackendTrace> trace_;
};

struct RunnerFixture {
    std::shared_ptr<FakeBackendTrace> trace = std::make_shared<FakeBackendTrace>();
    FakeBackend* backend = nullptr;
    std::unique_ptr<shinku::backend::BackendRunner> runner;

    RunnerFixture() {
        auto fake = std::make_unique<FakeBackend>(trace);
        backend = fake.get();
        runner = std::make_unique<shinku::backend::BackendRunner>(std::move(fake));
    }
};

} // namespace

TEST_CASE("BackendRunner initial state is Created") {
    RunnerFixture fixture;

    CHECK(fixture.runner->state() == shinku::backend::BackendState::Created);
    CHECK(fixture.trace->calls.empty());
}

TEST_CASE("BackendRunner start probes before starting backend") {
    RunnerFixture fixture;

    auto started = fixture.runner->start();

    REQUIRE(started.has_value());
    CHECK(fixture.runner->state() == shinku::backend::BackendState::Running);
    CHECK(fixture.trace->probe_calls == 1);
    CHECK(fixture.trace->start_calls == 1);
    CHECK(fixture.trace->calls == std::vector<std::string> { "probe", "start" });
}

TEST_CASE("BackendRunner rejects poll before start") {
    RunnerFixture fixture;

    auto polled = fixture.runner->poll_once();

    REQUIRE_FALSE(polled.has_value());
    CHECK(polled.error().code == shinku::backend::BackendErrorCode::InvalidState);
    CHECK(fixture.runner->state() == shinku::backend::BackendState::Created);
    CHECK(fixture.trace->poll_calls == 0);
}

TEST_CASE("BackendRunner forwards WorkDone and NoWork while running") {
    RunnerFixture fixture;
    REQUIRE(fixture.runner->start().has_value());

    fixture.backend->poll_result = shinku::backend::PollStatus::WorkDone;
    auto work_done = fixture.runner->poll_once();
    REQUIRE(work_done.has_value());
    CHECK(*work_done == shinku::backend::PollStatus::WorkDone);

    fixture.backend->poll_result = shinku::backend::PollStatus::NoWork;
    auto no_work = fixture.runner->poll_once();
    REQUIRE(no_work.has_value());
    CHECK(*no_work == shinku::backend::PollStatus::NoWork);
    CHECK(fixture.runner->state() == shinku::backend::BackendState::Running);
    CHECK(fixture.trace->poll_calls == 2);
}

TEST_CASE("BackendRunner poll failure moves state to Failed") {
    RunnerFixture fixture;
    REQUIRE(fixture.runner->start().has_value());
    fixture.backend->poll_result =
        std::unexpected(backend_error(shinku::backend::BackendErrorCode::PollFailed, "poll failed"));

    auto polled = fixture.runner->poll_once();

    REQUIRE_FALSE(polled.has_value());
    CHECK(polled.error().code == shinku::backend::BackendErrorCode::PollFailed);
    CHECK(fixture.runner->state() == shinku::backend::BackendState::Failed);
}

TEST_CASE("BackendRunner stop is idempotent") {
    RunnerFixture fixture;
    REQUIRE(fixture.runner->start().has_value());

    auto first_stop = fixture.runner->stop();
    auto second_stop = fixture.runner->stop();

    REQUIRE(first_stop.has_value());
    REQUIRE(second_stop.has_value());
    CHECK(fixture.runner->state() == shinku::backend::BackendState::Stopped);
    CHECK(fixture.trace->stop_calls == 1);
}

TEST_CASE("BackendRunner stop from Failed calls backend stop") {
    RunnerFixture fixture;
    REQUIRE(fixture.runner->start().has_value());
    fixture.backend->poll_result =
        std::unexpected(backend_error(shinku::backend::BackendErrorCode::PollFailed, "poll failed"));
    REQUIRE_FALSE(fixture.runner->poll_once().has_value());

    auto stopped = fixture.runner->stop();

    REQUIRE(stopped.has_value());
    CHECK(fixture.runner->state() == shinku::backend::BackendState::Stopped);
    CHECK(fixture.trace->stop_calls == 1);
}

TEST_CASE("BackendRunner destructor best-effort stops running backend") {
    auto trace = std::make_shared<FakeBackendTrace>();
    {
        auto fake = std::make_unique<FakeBackend>(trace);
        shinku::backend::BackendRunner runner(std::move(fake));
        REQUIRE(runner.start().has_value());
        CHECK(trace->stop_calls == 0);
    }

    CHECK(trace->stop_calls == 1);
}

TEST_CASE("BackendRunner start converts unsupported probe into error and Failed state") {
    RunnerFixture fixture;
    fixture.backend->probe_result = shinku::backend::ProbeResult {
        .status = shinku::backend::ProbeStatus::Unsupported,
        .message = "missing BPF arena",
    };

    auto started = fixture.runner->start();

    REQUIRE_FALSE(started.has_value());
    CHECK(started.error().code == shinku::backend::BackendErrorCode::Unsupported);
    CHECK(fixture.runner->state() == shinku::backend::BackendState::Failed);
    CHECK(fixture.trace->probe_calls == 1);
    CHECK(fixture.trace->start_calls == 0);
}

TEST_CASE("BackendRunner start failure moves state to Failed") {
    RunnerFixture fixture;
    fixture.backend->start_result =
        std::unexpected(backend_error(shinku::backend::BackendErrorCode::StartFailed, "start failed"));

    auto started = fixture.runner->start();

    REQUIRE_FALSE(started.has_value());
    CHECK(started.error().code == shinku::backend::BackendErrorCode::StartFailed);
    CHECK(fixture.runner->state() == shinku::backend::BackendState::Failed);
    CHECK(fixture.trace->probe_calls == 1);
    CHECK(fixture.trace->start_calls == 1);
}

TEST_CASE("BackendRunner rejects probe while running") {
    RunnerFixture fixture;
    REQUIRE(fixture.runner->start().has_value());

    auto probed = fixture.runner->probe();

    REQUIRE_FALSE(probed.has_value());
    CHECK(probed.error().code == shinku::backend::BackendErrorCode::InvalidState);
    CHECK(fixture.runner->state() == shinku::backend::BackendState::Running);
    CHECK(fixture.trace->probe_calls == 1);
}

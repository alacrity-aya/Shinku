// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/ebpf_backend.h"
#include "backend/backend_creation.h"
#include "backend/backend_runner.h"
#include "fake_ebpf_native_session.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using shinku::backend::BackendErrorCode;
using shinku::backend::BackendRunner;
using shinku::backend::BackendState;
using shinku::backend::StopCondition;
using shinku::backend::StopReason;
using shinku::backend::StopRequest;
using shinku::backend::ebpf::EbpfBackend;
using shinku::backend::ebpf::testing::FakeEbpfNativeSession;
using namespace std::chrono_literals;

shinku::config::EbpfConfig ebpf_config() {
    auto result = shinku::config::EbpfConfig::create({
        .iface = "eth0",
        .cleanup_interval = 10'000ms,
    });
    assert(result.has_value());
    return std::move(*result);
}

shinku::config::CacheConfig cache_config() {
    auto result = shinku::config::CacheConfig::create({
        .max_entries = 16'384,
        .max_response_bytes = 512,
        .cache_negative = true,
        .max_pending_queries = 8'192,
        .pending_query_timeout = 2'000ms,
    });
    assert(result.has_value());
    return std::move(*result);
}

class SequencedStopCondition final: public StopCondition {
public:
    explicit SequencedStopCondition(std::vector<std::optional<StopRequest>> results): results_(std::move(results)) {}

    std::optional<StopRequest> poll() noexcept override {
        if (next_ < results_.size())
            return results_[next_++];
        return StopRequest { .reason = StopReason::Manual };
    }

private:
    std::vector<std::optional<StopRequest>> results_;
    size_t next_ = 0;
};

struct BackendFixture {
    FakeEbpfNativeSession* session = nullptr;
    std::unique_ptr<BackendRunner> runner;

    explicit BackendFixture(shinku::config::EbpfConfig config = ebpf_config()) {
        auto fake = std::make_unique<FakeEbpfNativeSession>();
        session = fake.get();
        auto backend = std::make_unique<EbpfBackend>(std::move(config), cache_config(), std::move(fake));
        runner = std::make_unique<BackendRunner>(std::move(backend));
    }
};

bool called_after(const std::vector<std::string>& calls, std::string_view first, std::string_view second) {
    const auto first_position = std::find(calls.begin(), calls.end(), first);
    const auto second_position = std::find(calls.begin(), calls.end(), second);
    return first_position != calls.end() && second_position != calls.end() && first_position < second_position;
}

} // namespace

TEST_CASE("EbpfBackend lifecycle is driven through BackendRunner") {
    BackendFixture fixture;
    fixture.session->packet_poll_results.emplace_back(1);
    SequencedStopCondition stop_condition({ std::nullopt, std::nullopt, StopRequest { .reason = StopReason::Signal } });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE(result.has_value());
    CHECK(result->accepted_stop.reason == StopReason::Signal);
    CHECK(fixture.runner->state() == BackendState::Stopped);
    CHECK(fixture.session->probed_interface == "eth0");
    CHECK(fixture.session->indexed_interface == "eth0");
    REQUIRE(fixture.session->configured_skeleton.has_value());
    CHECK(fixture.session->configured_skeleton->cache_layout.entry_capacity == 16'384);
    CHECK(fixture.session->configured_skeleton->cache_layout.response_capacity == 512);
    CHECK(fixture.session->configured_skeleton->pending_capacity == 8'192);
    CHECK(fixture.session->configured_skeleton->pending_timeout_ns == 2'000'000'000ULL);
    CHECK(fixture.session->attached_ifindex == 7);
    CHECK(fixture.session->log_poll_timeout_ms == 0);
    CHECK(fixture.session->packet_poll_timeout_ms == 100);
    CHECK(called_after(fixture.session->calls, "prepare_skeleton", "create_log_ring"));
    CHECK(called_after(fixture.session->calls, "create_log_ring", "attach_xdp"));
    CHECK(called_after(fixture.session->calls, "attach_tcx", "create_packet_ring"));
    CHECK(called_after(fixture.session->calls, "create_packet_ring", "poll_packet_ring"));
    CHECK(called_after(fixture.session->calls, "poll_packet_ring", "close_packet_ring"));
    CHECK(called_after(fixture.session->calls, "close_packet_ring", "release"));
}

TEST_CASE("EbpfBackend maps capability conclusions without entering start") {
    SECTION("missing privileges") {
        BackendFixture fixture;
        fixture.session->privilege_result = false;
        SequencedStopCondition stop_condition({ std::nullopt });

        auto result = fixture.runner->run(stop_condition);

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::PermissionDenied);
        CHECK(fixture.session->calls == std::vector<std::string> { "probe_privileges" });
    }

    SECTION("missing interface") {
        BackendFixture fixture;
        fixture.session->interface_result = false;
        SequencedStopCondition stop_condition({ std::nullopt });

        auto result = fixture.runner->run(stop_condition);

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::WrongConfig);
        CHECK(result.error().message.find("eth0") != std::string::npos);
    }

    SECTION("unsupported arena") {
        BackendFixture fixture;
        fixture.session->arena_result = false;
        SequencedStopCondition stop_condition({ std::nullopt });

        auto result = fixture.runner->run(stop_condition);

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::Unsupported);
    }
}

TEST_CASE("EbpfBackend preserves probe operation causes") {
    BackendFixture fixture;
    const auto cause = std::make_error_code(std::errc::io_error);
    fixture.session->arena_result = std::unexpected(cause);
    SequencedStopCondition stop_condition({ std::nullopt });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::ProbeFailed);
    CHECK(result.error().cause == cause);
}

TEST_CASE("EbpfBackend leaves partial native session state for runner cleanup") {
    BackendFixture fixture;
    const auto cause = std::make_error_code(std::errc::not_enough_memory);
    fixture.session->packet_ring_result = std::unexpected(cause);
    SequencedStopCondition stop_condition({ std::nullopt });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StartFailed);
    CHECK(result.error().cause == cause);
    CHECK(fixture.runner->state() == BackendState::Failed);
    CHECK(called_after(fixture.session->calls, "create_packet_ring", "release"));
}

TEST_CASE("EbpfBackend treats log ring creation failure as fatal") {
    BackendFixture fixture;
    const auto cause = std::make_error_code(std::errc::not_enough_memory);
    fixture.session->log_ring_result = std::unexpected(cause);
    SequencedStopCondition stop_condition({ std::nullopt });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StartFailed);
    CHECK(result.error().cause == cause);
    CHECK(called_after(fixture.session->calls, "create_log_ring", "release"));
}

TEST_CASE("EbpfBackend owns XDP retry and backoff policy") {
    BackendFixture fixture;
    const auto busy = std::make_error_code(std::errc::device_or_resource_busy);
    fixture.session->xdp_results = { std::unexpected(busy), std::unexpected(busy), {} };
    SequencedStopCondition stop_condition({ std::nullopt, StopRequest { .reason = StopReason::Manual } });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE(result.has_value());
    CHECK(fixture.session->waits == std::vector<std::chrono::milliseconds> { 50ms, 100ms });
    CHECK(std::count(fixture.session->calls.begin(), fixture.session->calls.end(), "attach_xdp") == 3);
}

TEST_CASE("EbpfBackend falls back from unsupported TCX to legacy TC") {
    BackendFixture fixture;
    fixture.session->tcx_results = {
        std::unexpected(std::make_error_code(std::errc::operation_not_supported)),
    };
    SequencedStopCondition stop_condition({ std::nullopt, StopRequest { .reason = StopReason::Manual } });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE(result.has_value());
    CHECK(called_after(fixture.session->calls, "attach_tcx", "attach_legacy_tc"));
    CHECK(std::count(fixture.session->calls.begin(), fixture.session->calls.end(), "attach_legacy_tc") == 1);
}

TEST_CASE("EbpfBackend preserves packet ring polling behavior") {
    SECTION("interrupted poll is no work") {
        BackendFixture fixture;
        fixture.session->packet_poll_results.emplace_back(std::unexpected(std::make_error_code(std::errc::interrupted))
        );
        SequencedStopCondition stop_condition(
            { std::nullopt, std::nullopt, StopRequest { .reason = StopReason::Manual } }
        );

        auto result = fixture.runner->run(stop_condition);

        REQUIRE(result.has_value());
        CHECK(fixture.runner->state() == BackendState::Stopped);
    }

    SECTION("other poll error fails the runner and releases the session") {
        BackendFixture fixture;
        const auto cause = std::make_error_code(std::errc::io_error);
        fixture.session->packet_poll_results.emplace_back(std::unexpected(cause));
        SequencedStopCondition stop_condition({ std::nullopt, std::nullopt });

        auto result = fixture.runner->run(stop_condition);

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::PollFailed);
        CHECK(result.error().cause == cause);
        CHECK(fixture.runner->state() == BackendState::Failed);
        CHECK(
            std::find(fixture.session->calls.begin(), fixture.session->calls.end(), "release")
            != fixture.session->calls.end()
        );
    }
}

TEST_CASE("EbpfBackend uses the configured packet poll timeout") {
    auto config = shinku::config::EbpfConfig::create({
        .iface = "eth0",
        .cleanup_interval = 10'000ms,
        .packet_poll_timeout = 250ms,
    });
    REQUIRE(config.has_value());
    BackendFixture fixture(std::move(*config));
    SequencedStopCondition stop_condition({ std::nullopt, std::nullopt, StopRequest { .reason = StopReason::Manual } });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE(result.has_value());
    CHECK(fixture.session->log_poll_timeout_ms == 0);
    CHECK(fixture.session->packet_poll_timeout_ms == 250);
}

TEST_CASE("EbpfBackend preserves log ring polling behavior") {
    SECTION("interrupted log poll short-circuits packet polling") {
        BackendFixture fixture;
        fixture.session->log_poll_results.emplace_back(std::unexpected(std::make_error_code(std::errc::interrupted)));
        SequencedStopCondition stop_condition(
            { std::nullopt, std::nullopt, StopRequest { .reason = StopReason::Manual } }
        );

        auto result = fixture.runner->run(stop_condition);

        REQUIRE(result.has_value());
        CHECK(fixture.session->log_poll_timeout_ms == 0);
        CHECK(std::count(fixture.session->calls.begin(), fixture.session->calls.end(), "poll_packet_ring") == 0);
    }

    SECTION("other log poll errors do not prevent packet polling") {
        BackendFixture fixture;
        fixture.session->log_poll_results.emplace_back(std::unexpected(std::make_error_code(std::errc::io_error)));
        fixture.session->packet_poll_results.emplace_back(1);
        SequencedStopCondition stop_condition(
            { std::nullopt, std::nullopt, StopRequest { .reason = StopReason::Manual } }
        );

        auto result = fixture.runner->run(stop_condition);

        REQUIRE(result.has_value());
        CHECK(fixture.session->log_poll_timeout_ms == 0);
        CHECK(std::count(fixture.session->calls.begin(), fixture.session->calls.end(), "poll_packet_ring") == 1);
    }
}

TEST_CASE("EbpfBackend maps native session release failure") {
    BackendFixture fixture;
    const auto release_error = std::make_error_code(std::errc::io_error);
    fixture.session->release_results.emplace_back(std::unexpected(release_error));
    SequencedStopCondition stop_condition({ std::nullopt, StopRequest { .reason = StopReason::Manual } });

    auto result = fixture.runner->run(stop_condition);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StopFailed);
    CHECK(result.error().cause == release_error);
    CHECK(fixture.runner->state() == BackendState::Failed);
    CHECK(std::count(fixture.session->calls.begin(), fixture.session->calls.end(), "release") == 1);
}

TEST_CASE("make_backend dispatches the validated backend alternative") {
    const shinku::config::Config config = {
        .backend = ebpf_config(),
        .cache = cache_config(),
    };
    auto backend = shinku::backend::make_backend(config);
    REQUIRE(backend.has_value());
    CHECK(*backend != nullptr);

    const shinku::config::Config dpdk_config = {
        .backend = shinku::config::DpdkBackendSelection {},
        .cache = cache_config(),
    };
    auto dpdk_backend = shinku::backend::make_backend(dpdk_config);
    REQUIRE(dpdk_backend.has_value());
    CHECK(*dpdk_backend != nullptr);

    const std::array<std::string, 1> misplaced_dpdk_argument { "--no-huge" };
    auto invalid_ebpf = shinku::backend::make_backend(config, misplaced_dpdk_argument);
    REQUIRE_FALSE(invalid_ebpf.has_value());
    CHECK(invalid_ebpf.error().code == BackendErrorCode::WrongConfig);
}

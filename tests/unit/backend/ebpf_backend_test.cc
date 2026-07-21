// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/ebpf_backend.h"
#include "backend/backend_creation.h"
#include "backend/ebpf/ebpf_loader_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <chrono>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace {

using shinku::backend::BackendErrorCode;
using shinku::backend::PollStatus;
using shinku::backend::ebpf::CapabilityProbeResult;
using shinku::backend::ebpf::EbpfBackend;
using shinku::backend::ebpf::EbpfLoaderConfig;
using shinku::backend::ebpf::EbpfLoaderOps;

struct FakeOpsState {
    CapabilityProbeResult privilege_result = true;
    CapabilityProbeResult interface_result = true;
    CapabilityProbeResult arena_result = true;
    int setup_result = 0;
    int cleanup_thread_result = 0;
    int log_poll_result = 0;
    int packet_poll_result = 0;
    int cleanup_calls = 0;
    int packet_poll_calls = 0;
    int log_timeout_ms = 0;
    int packet_timeout_ms = 0;
    uint32_t cleanup_interval_ms = 0;
    std::string probed_iface;
    EbpfLoaderConfig setup_config;
    std::vector<std::string> calls;
};

FakeOpsState& state(void* context) {
    return *static_cast<FakeOpsState*>(context);
}

CapabilityProbeResult probe_privileges(void* context) {
    state(context).calls.emplace_back("probe_privileges");
    return state(context).privilege_result;
}

CapabilityProbeResult probe_interface(void* context, std::string_view iface) {
    state(context).calls.emplace_back("probe_interface");
    state(context).probed_iface = iface;
    return state(context).interface_result;
}

CapabilityProbeResult probe_arena(void* context) {
    state(context).calls.emplace_back("probe_arena");
    return state(context).arena_result;
}

int setup(void* context, [[maybe_unused]] bpf_ctx* bpf_context, const EbpfLoaderConfig& config) {
    state(context).calls.emplace_back("setup");
    state(context).setup_config = config;
    return state(context).setup_result;
}

int start_cleanup_thread(void* context, [[maybe_unused]] bpf_ctx* bpf_context, uint32_t interval_ms) {
    state(context).calls.emplace_back("start_cleanup_thread");
    state(context).cleanup_interval_ms = interval_ms;
    return state(context).cleanup_thread_result;
}

int poll_log_ring(void* context, [[maybe_unused]] bpf_ctx* bpf_context, int timeout_ms) {
    state(context).calls.emplace_back("poll_log_ring");
    state(context).log_timeout_ms = timeout_ms;
    return state(context).log_poll_result;
}

int poll_packet_ring(void* context, [[maybe_unused]] bpf_ctx* bpf_context, int timeout_ms) {
    state(context).calls.emplace_back("poll_packet_ring");
    state(context).packet_poll_calls++;
    state(context).packet_timeout_ms = timeout_ms;
    return state(context).packet_poll_result;
}

void cleanup(void* context, [[maybe_unused]] bpf_ctx* bpf_context) {
    state(context).calls.emplace_back("cleanup");
    state(context).cleanup_calls++;
}

const EbpfLoaderOps kFakeOps = {
    .has_required_privileges = probe_privileges,
    .interface_exists = probe_interface,
    .arena_supported = probe_arena,
    .setup = setup,
    .start_cleanup_thread = start_cleanup_thread,
    .poll_log_ring = poll_log_ring,
    .poll_packet_ring = poll_packet_ring,
    .cleanup = cleanup,
};

shinku::config::EbpfConfig ebpf_config() {
    return shinku::config::EbpfConfig {
        .iface = "eth0",
        .arena_pages = 2112,
        .cleanup_interval = std::chrono::milliseconds(10'000),
    };
}

shinku::config::CacheConfig cache_config() {
    return shinku::config::CacheConfig {
        .max_entries = 16'384,
        .max_response_bytes = 512,
        .cache_negative = true,
    };
}

std::unique_ptr<EbpfBackend> make_fake_backend(FakeOpsState& ops_state) {
    return std::make_unique<EbpfBackend>(ebpf_config(), cache_config(), kFakeOps, &ops_state);
}

} // namespace

namespace shinku::backend::ebpf {

const EbpfLoaderOps& production_ebpf_loader_ops() noexcept {
    return kFakeOps;
}

} // namespace shinku::backend::ebpf

TEST_CASE("EbpfBackend probe preserves operation order") {
    FakeOpsState ops_state;
    auto backend = make_fake_backend(ops_state);

    auto result = backend->probe();

    REQUIRE(result.has_value());
    CHECK(ops_state.calls == std::vector<std::string> {
                                 "probe_privileges",
                                 "probe_interface",
                                 "probe_arena",
                             });
    CHECK(ops_state.probed_iface == "eth0");
}

TEST_CASE("EbpfBackend maps negative capability conclusions") {
    SECTION("missing privileges") {
        FakeOpsState ops_state;
        ops_state.privilege_result = false;
        auto backend = make_fake_backend(ops_state);

        auto result = backend->probe();

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::PermissionDenied);
        CHECK_FALSE(result.error().cause.has_value());
        CHECK(ops_state.calls == std::vector<std::string> { "probe_privileges" });
    }

    SECTION("missing interface") {
        FakeOpsState ops_state;
        ops_state.interface_result = false;
        auto backend = make_fake_backend(ops_state);

        auto result = backend->probe();

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::WrongConfig);
        CHECK_FALSE(result.error().cause.has_value());
        CHECK(result.error().message.find("eth0") != std::string::npos);
    }

    SECTION("unsupported arena") {
        FakeOpsState ops_state;
        ops_state.arena_result = false;
        auto backend = make_fake_backend(ops_state);

        auto result = backend->probe();

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::Unsupported);
        CHECK_FALSE(result.error().cause.has_value());
    }
}

TEST_CASE("EbpfBackend maps probe operation errors with causes") {
    const auto cause = std::make_error_code(std::errc::io_error);

    SECTION("privilege operation") {
        FakeOpsState ops_state;
        ops_state.privilege_result = std::unexpected(cause);
        auto backend = make_fake_backend(ops_state);
        auto result = backend->probe();
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::ProbeFailed);
        CHECK(result.error().cause == cause);
    }

    SECTION("interface operation") {
        FakeOpsState ops_state;
        ops_state.interface_result = std::unexpected(cause);
        auto backend = make_fake_backend(ops_state);
        auto result = backend->probe();
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::ProbeFailed);
        CHECK(result.error().cause == cause);
    }

    SECTION("arena operation") {
        FakeOpsState ops_state;
        ops_state.arena_result = std::unexpected(cause);
        auto backend = make_fake_backend(ops_state);
        auto result = backend->probe();
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == BackendErrorCode::ProbeFailed);
        CHECK(result.error().cause == cause);
    }
}

TEST_CASE("EbpfBackend setup failure keeps private loader code out of cause") {
    FakeOpsState ops_state;
    ops_state.setup_result = -3;
    auto backend = make_fake_backend(ops_state);

    auto result = backend->start();

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StartFailed);
    CHECK(result.error().message.find("-3") != std::string::npos);
    CHECK_FALSE(result.error().cause.has_value());
    REQUIRE(backend->stop().has_value());
    CHECK(ops_state.cleanup_calls == 0);
}

TEST_CASE("EbpfBackend cleanup thread failure remains available for runner cleanup") {
    FakeOpsState ops_state;
    ops_state.cleanup_thread_result = -EAGAIN;
    auto backend = make_fake_backend(ops_state);

    auto result = backend->start();

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StartFailed);
    REQUIRE(result.error().cause.has_value());
    CHECK(result.error().cause->value() == EAGAIN);
    CHECK(ops_state.setup_config.iface == "eth0");
    CHECK(ops_state.setup_config.arena_pages == 2112);
    CHECK(ops_state.cleanup_interval_ms == 10'000);

    REQUIRE(backend->stop().has_value());
    CHECK(ops_state.cleanup_calls == 1);
}

TEST_CASE("EbpfBackend preserves ring polling behavior") {
    FakeOpsState ops_state;
    auto backend = make_fake_backend(ops_state);
    REQUIRE(backend->start().has_value());

    ops_state.log_poll_result = 1;
    auto work = backend->poll_once();
    REQUIRE(work.has_value());
    CHECK(*work == PollStatus::WorkDone);
    CHECK(ops_state.log_timeout_ms == 100);
    CHECK(ops_state.packet_timeout_ms == 100);

    ops_state.log_poll_result = 0;
    ops_state.packet_poll_result = 0;
    auto no_work = backend->poll_once();
    REQUIRE(no_work.has_value());
    CHECK(*no_work == PollStatus::NoWork);

    ops_state.log_poll_result = -EINTR;
    const int packet_calls_before_log_interrupt = ops_state.packet_poll_calls;
    auto interrupted_log = backend->poll_once();
    REQUIRE(interrupted_log.has_value());
    CHECK(*interrupted_log == PollStatus::NoWork);
    CHECK(ops_state.packet_poll_calls == packet_calls_before_log_interrupt);

    ops_state.log_poll_result = -EIO;
    ops_state.packet_poll_result = 2;
    auto nonfatal_log_error = backend->poll_once();
    REQUIRE(nonfatal_log_error.has_value());
    CHECK(*nonfatal_log_error == PollStatus::WorkDone);

    ops_state.log_poll_result = 0;
    ops_state.packet_poll_result = -EINTR;
    auto interrupted_packet = backend->poll_once();
    REQUIRE(interrupted_packet.has_value());
    CHECK(*interrupted_packet == PollStatus::NoWork);

    ops_state.packet_poll_result = -EIO;
    auto packet_error = backend->poll_once();
    REQUIRE_FALSE(packet_error.has_value());
    CHECK(packet_error.error().code == BackendErrorCode::PollFailed);
    REQUIRE(packet_error.error().cause.has_value());
    CHECK(packet_error.error().cause->value() == EIO);

    REQUIRE(backend->stop().has_value());
    REQUIRE(backend->stop().has_value());
    CHECK(ops_state.cleanup_calls == 1);
}

TEST_CASE("make_backend rejects mismatch and unavailable DPDK") {
    const shinku::config::Config mismatch = {
        .backend = shinku::config::BackendKind::Ebpf,
        .backend_config = shinku::config::DpdkConfig { .client_port = 0, .server_port = 1 },
        .cache = cache_config(),
    };
    auto mismatched = shinku::backend::make_backend(mismatch);
    REQUIRE_FALSE(mismatched.has_value());
    CHECK(mismatched.error().code == BackendErrorCode::WrongConfig);

    const shinku::config::Config dpdk = {
        .backend = shinku::config::BackendKind::Dpdk,
        .backend_config = shinku::config::DpdkConfig { .client_port = 0, .server_port = 1 },
        .cache = cache_config(),
    };
    auto unavailable = shinku::backend::make_backend(dpdk);
    REQUIRE_FALSE(unavailable.has_value());
    CHECK(unavailable.error().code == BackendErrorCode::Unsupported);
}

TEST_CASE("make_backend constructs selected eBPF backend without probing") {
    const shinku::config::Config config = {
        .backend = shinku::config::BackendKind::Ebpf,
        .backend_config = ebpf_config(),
        .cache = cache_config(),
    };

    auto backend = shinku::backend::make_backend(config);

    REQUIRE(backend.has_value());
    CHECK(*backend != nullptr);
}

TEST_CASE("make_backend rejects cleanup intervals outside the C loader range") {
    auto invalid_ebpf_config = ebpf_config();
    invalid_ebpf_config.cleanup_interval = std::chrono::milliseconds(-1);
    const shinku::config::Config config = {
        .backend = shinku::config::BackendKind::Ebpf,
        .backend_config = std::move(invalid_ebpf_config),
        .cache = cache_config(),
    };

    auto backend = shinku::backend::make_backend(config);

    REQUIRE_FALSE(backend.has_value());
    CHECK(backend.error().code == BackendErrorCode::WrongConfig);
}

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_backend.h"
#include "backend/backend_runner.h"
#include "backend/dpdk/dpdk_native_session.h"
#include "backend/dpdk/dpdk_packet_path.h"
#include "backend/dpdk/dpdk_scheduler.h"
#include "config/config.h"

#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <deque>
#include <expected>
#include <memory>
#include <optional>
#include <rte_mbuf.h>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using shinku::backend::BackendError;
using shinku::backend::BackendErrorCode;
using shinku::backend::BackendRunner;
using shinku::backend::StopCondition;
using shinku::backend::StopReason;
using shinku::backend::StopRequest;
using shinku::backend::dpdk::DpdkNativeError;
using shinku::backend::dpdk::DpdkNativeSession;
using shinku::backend::dpdk::PortSide;

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

class FakeDpdkNativeSession final: public DpdkNativeSession {
public:
    std::expected<void, DpdkNativeError> start_result;
    std::expected<void, DpdkNativeError> release_result;
    std::array<std::deque<rte_mbuf*>, 2> incoming;
    std::array<uint16_t, 2> tx_limits { UINT16_MAX, UINT16_MAX };
    std::vector<std::string> calls;
    std::vector<std::string> eal_arguments;
    std::vector<rte_mbuf*> freed;
    std::array<std::vector<rte_mbuf*>, 2> transmitted;
    std::array<std::vector<uint16_t>, 2> receive_capacities;
    std::expected<void, DpdkNativeError> start(std::span<const std::string> arguments) override {
        calls.emplace_back("start");
        eal_arguments.assign(arguments.begin(), arguments.end());
        return start_result;
    }

    uint16_t receive(PortSide side, rte_mbuf** packets, uint16_t capacity) noexcept override {
        calls.push_back(side == PortSide::Client ? "rx-client" : "rx-service");
        const size_t index = side_index(side);
        receive_capacities[index].push_back(capacity);
        const uint16_t count = std::min<uint16_t>(capacity, static_cast<uint16_t>(incoming[index].size()));
        for (uint16_t packet = 0; packet < count; ++packet) {
            packets[packet] = incoming[index].front();
            incoming[index].pop_front();
        }
        return count;
    }

    uint16_t transmit(PortSide side, rte_mbuf** packets, uint16_t count) noexcept override {
        calls.push_back(side == PortSide::Client ? "tx-client" : "tx-service");
        const size_t index = side_index(side);
        const uint16_t accepted = std::min(count, tx_limits[index]);
        transmitted[index].insert(transmitted[index].end(), packets, packets + accepted);
        return accepted;
    }

    void free_packet(rte_mbuf* packet) noexcept override {
        calls.emplace_back("free");
        freed.push_back(packet);
    }

    std::string_view port_identity(PortSide side) const noexcept override {
        return side == PortSide::Client ? "fake-client" : "fake-service";
    }

    std::expected<void, DpdkNativeError> release() override {
        calls.emplace_back("release");
        return release_result;
    }

private:
    static size_t side_index(PortSide side) noexcept {
        return side == PortSide::Client ? 0 : 1;
    }
};

rte_mbuf single_segment_packet(uint16_t size = 64) {
    rte_mbuf packet {};
    packet.nb_segs = 1;
    packet.data_len = size;
    packet.pkt_len = size;
    packet.next = nullptr;
    return packet;
}

class TraceTask final: public shinku::backend::dpdk::DpdkPollTask {
public:
    TraceTask(std::vector<int>& trace, int value): trace_(&trace), value_(value) {}

    std::expected<void, BackendError> run() override {
        trace_->push_back(value_);
        return result;
    }

    std::expected<void, BackendError> result;

private:
    std::vector<int>* trace_;
    int value_;
};

std::unique_ptr<shinku::backend::dpdk::DpdkBackend>
make_backend(std::unique_ptr<DpdkNativeSession> session, std::span<const std::string> arguments = {}) {
    return std::make_unique<shinku::backend::dpdk::DpdkBackend>(arguments, std::move(session));
}

} // namespace

TEST_CASE("DPDK packet path closes burst ownership in one quantum") {
    FakeDpdkNativeSession session;
    shinku::backend::dpdk::DpdkPacketPath path(session, PortSide::Client, PortSide::Service);
    std::array<rte_mbuf, 4> packets;
    for (rte_mbuf& packet: packets) {
        packet = single_segment_packet();
        session.incoming[0].push_back(&packet);
    }

    SECTION("complete TX transfers every packet") {
        REQUIRE(path.run().has_value());
        CHECK(session.receive_capacities[0] == std::vector<uint16_t> { 32 });
        CHECK(session.transmitted[1].size() == packets.size());
        CHECK(session.freed.empty());
    }

    SECTION("partial TX frees only the unaccepted suffix") {
        session.tx_limits[1] = 2;
        REQUIRE(path.run().has_value());
        CHECK(session.transmitted[1].size() == 2);
        CHECK(session.freed == std::vector<rte_mbuf*> { &packets[2], &packets[3] });
    }

    SECTION("zero TX frees the complete burst") {
        session.tx_limits[1] = 0;
        REQUIRE(path.run().has_value());
        CHECK(session.transmitted[1].empty());
        CHECK(session.freed.size() == packets.size());
    }
}

TEST_CASE("DPDK packet path performs no TX for an empty burst") {
    FakeDpdkNativeSession session;
    shinku::backend::dpdk::DpdkPacketPath path(session, PortSide::Client, PortSide::Service);

    REQUIRE(path.run().has_value());

    CHECK(session.calls == std::vector<std::string> { "rx-client" });
    CHECK(session.transmitted[1].empty());
    CHECK(session.freed.empty());
}

TEST_CASE("DPDK packet path drops frame-contract violations and continues") {
    FakeDpdkNativeSession session;
    shinku::backend::dpdk::DpdkPacketPath path(session, PortSide::Client, PortSide::Service);
    rte_mbuf valid_before = single_segment_packet();
    rte_mbuf multi_segment = single_segment_packet();
    rte_mbuf tail = single_segment_packet();
    multi_segment.nb_segs = 2;
    multi_segment.next = &tail;
    multi_segment.pkt_len += tail.pkt_len;
    rte_mbuf oversized = single_segment_packet(1519);
    rte_mbuf valid_after = single_segment_packet();
    session.incoming[0] = { &valid_before, &multi_segment, &oversized, &valid_after };

    REQUIRE(path.run().has_value());

    CHECK(session.freed == std::vector<rte_mbuf*> { &multi_segment, &oversized });
    CHECK(session.transmitted[1] == std::vector<rte_mbuf*> { &valid_before, &valid_after });
}

TEST_CASE("DPDK scheduler preserves client service cache pending order") {
    std::vector<int> trace;
    TraceTask client(trace, 1);
    TraceTask service(trace, 2);
    TraceTask cache(trace, 3);
    TraceTask pending(trace, 4);
    shinku::backend::dpdk::DpdkCooperativeScheduler scheduler({ &client, &service, &cache, &pending });

    REQUIRE(scheduler.run_quantum().has_value());
    CHECK(trace == std::vector<int> { 1, 2, 3, 4 });
}

TEST_CASE("DPDK scheduler returns the first task failure without running later tasks") {
    std::vector<int> trace;
    TraceTask client(trace, 1);
    TraceTask service(trace, 2);
    TraceTask cache(trace, 3);
    service.result = std::unexpected(BackendError {
        .code = BackendErrorCode::PollFailed,
        .message = "service failed",
        .cause = std::nullopt,
    });
    shinku::backend::dpdk::DpdkCooperativeScheduler scheduler({ &client, &service, &cache, nullptr });

    auto result = scheduler.run_quantum();

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().message == "service failed");
    CHECK(trace == std::vector<int> { 1, 2 });
}

TEST_CASE("DPDK backend forwards native EAL arguments unchanged") {
    auto session = std::make_unique<FakeDpdkNativeSession>();
    auto* trace = session.get();
    const std::vector<std::string> arguments {
        "--no-huge",
        "--no-pci",
        "--vdev=net_ring0",
        "--vdev=net_ring1",
    };
    BackendRunner runner(make_backend(std::move(session), arguments));
    SequencedStopCondition stop({ std::nullopt, StopRequest { .reason = StopReason::Manual } });

    REQUIRE(runner.run(stop).has_value());
    CHECK(trace->eal_arguments == arguments);
    CHECK(trace->calls == std::vector<std::string> { "start", "release" });
}

TEST_CASE("DPDK backend maps lifecycle failures and preserves cleanup") {
    auto session = std::make_unique<FakeDpdkNativeSession>();
    auto* trace = session.get();
    trace->start_result = std::unexpected(DpdkNativeError {
        .operation = "port validation",
        .detail = "configured DPDK Port ID 3 does not exist",
        .cause = std::make_error_code(std::errc::no_such_device),
    });
    BackendRunner runner(make_backend(std::move(session)));
    SequencedStopCondition stop({ std::nullopt });

    auto result = runner.run(stop);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StartFailed);
    CHECK(result.error().message.contains("Port ID 3"));
    CHECK(trace->calls == std::vector<std::string> { "start", "release" });
}

TEST_CASE("DPDK backend runs one bounded client-first quantum") {
    auto session = std::make_unique<FakeDpdkNativeSession>();
    auto* trace = session.get();
    std::array<rte_mbuf, 64> packets;
    for (size_t index = 0; index < packets.size(); ++index) {
        packets[index] = single_segment_packet();
        trace->incoming[index < 32 ? 0 : 1].push_back(&packets[index]);
    }
    BackendRunner runner(make_backend(std::move(session)));
    SequencedStopCondition stop({ std::nullopt, std::nullopt, StopRequest { .reason = StopReason::Manual } });

    REQUIRE(runner.run(stop).has_value());
    CHECK(trace->receive_capacities[0] == std::vector<uint16_t> { 32 });
    CHECK(trace->receive_capacities[1] == std::vector<uint16_t> { 32 });
    CHECK(trace->transmitted[1].size() == 32);
    CHECK(trace->transmitted[0].size() == 32);
    CHECK(
        trace->calls
        == std::vector<std::string> { "start", "rx-client", "tx-service", "rx-service", "tx-client", "release" }
    );
}

TEST_CASE("DPDK backend reports native release failure") {
    auto session = std::make_unique<FakeDpdkNativeSession>();
    auto* trace = session.get();
    trace->release_result = std::unexpected(DpdkNativeError {
        .operation = "port close",
        .detail = "fake-service",
        .cause = std::make_error_code(std::errc::device_or_resource_busy),
    });
    BackendRunner runner(make_backend(std::move(session)));
    SequencedStopCondition stop({ std::nullopt, StopRequest { .reason = StopReason::Manual } });

    auto result = runner.run(stop);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StopFailed);
    CHECK(result.error().message.contains("port close"));
    CHECK(result.error().message.contains("fake-service"));
    CHECK(trace->calls == std::vector<std::string> { "start", "release" });
}

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_runner.h"
#include "backend/dpdk/dpdk_backend.h"
#include "backend/dpdk/dpdk_eal.h"
#include "backend/dpdk/dpdk_packet_path.h"
#include "backend/dpdk/dpdk_packet_pool.h"
#include "backend/dpdk/dpdk_port.h"
#include "backend/dpdk/dpdk_scheduler.h"
#include "config/config.h"

#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
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
using shinku::backend::dpdk::DpdkDescriptorCounts;
using shinku::backend::dpdk::DpdkEal;
using shinku::backend::dpdk::DpdkError;
using shinku::backend::dpdk::DpdkPacketPool;
using shinku::backend::dpdk::DpdkPort;
using shinku::backend::dpdk::DnsPacketDirection;

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

class FakeDpdkEal final: public DpdkEal {
public:
    std::expected<void, DpdkError> initialize_result;
    std::expected<void, DpdkError> close_result;
    std::vector<std::string> arguments;
    std::vector<std::string> calls;

    std::expected<void, DpdkError> initialize(std::span<const std::string> eal_arguments) override {
        calls.emplace_back("initialize");
        arguments.assign(eal_arguments.begin(), eal_arguments.end());
        return initialize_result;
    }

    int main_socket_id() const noexcept override {
        return -1;
    }

    std::expected<void, DpdkError> close() override {
        calls.emplace_back("close");
        return close_result;
    }
};

class FakeDpdkPacketPool final: public DpdkPacketPool {
public:
    std::expected<void, DpdkError> create_result;
    std::expected<void, DpdkError> close_result;
    bool owns = false;

    std::expected<void, DpdkError>
    create(const std::array<DpdkDescriptorCounts, 2>&, int) override {
        if (create_result)
            owns = true;
        return create_result;
    }

    bool owns_resources() const noexcept override {
        return owns;
    }

    std::expected<void, DpdkError> close() override {
        auto result = close_result;
        if (result)
            owns = false;
        return result;
    }
};

class FakeDpdkPort final: public DpdkPort {
public:
    explicit FakeDpdkPort(std::string identity): identity_(std::move(identity)) {}

    std::expected<DpdkDescriptorCounts, DpdkError> configure_result {
        DpdkDescriptorCounts { .rx = 32, .tx = 32 }
    };
    std::expected<void, DpdkError> setup_result;
    std::expected<void, DpdkError> start_result;
    std::expected<void, DpdkError> close_result;
    std::deque<rte_mbuf*> incoming;
    std::vector<rte_mbuf*> transmitted;
    std::vector<rte_mbuf*> freed;
    std::vector<uint16_t> receive_capacities;
    uint16_t tx_limit = UINT16_MAX;

    std::expected<DpdkDescriptorCounts, DpdkError> configure() override {
        if (configure_result)
            owns = true;
        return configure_result;
    }

    std::expected<void, DpdkError> setup_queues(int) override {
        return setup_result;
    }

    std::expected<void, DpdkError> start() override {
        return start_result;
    }

    void log_link_state() const noexcept override {}

    uint16_t receive(std::span<rte_mbuf*> packets) noexcept override {
        receive_capacities.push_back(static_cast<uint16_t>(packets.size()));
        const uint16_t count = std::min<uint16_t>(static_cast<uint16_t>(packets.size()), incoming.size());
        for (uint16_t index = 0; index < count; ++index) {
            packets[index] = incoming.front();
            incoming.pop_front();
        }
        return count;
    }

    uint16_t transmit(std::span<rte_mbuf*> packets) noexcept override {
        const uint16_t accepted = std::min<uint16_t>(static_cast<uint16_t>(packets.size()), tx_limit);
        transmitted.insert(transmitted.end(), packets.begin(), packets.begin() + accepted);
        return accepted;
    }

    void free_packet(rte_mbuf& packet) noexcept override {
        freed.push_back(&packet);
    }

    std::string_view identity() const noexcept override {
        return identity_;
    }

    bool owns_resources() const noexcept override {
        return owns;
    }

    std::expected<void, DpdkError> close() override {
        auto result = close_result;
        if (result)
            owns = false;
        return result;
    }

private:
    std::string identity_;
    bool owns = false;
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
    TraceTask(std::vector<int>& trace, int value): trace_(trace), value_(value) {}

    std::expected<void, BackendError> run() override {
        trace_.push_back(value_);
        return result;
    }

    std::expected<void, BackendError> result;

private:
    std::vector<int>& trace_;
    int value_;
};

std::unique_ptr<shinku::backend::dpdk::DpdkBackend> make_backend(
    std::unique_ptr<FakeDpdkEal> eal,
    std::unique_ptr<FakeDpdkPacketPool> packet_pool,
    std::unique_ptr<FakeDpdkPort> client,
    std::unique_ptr<FakeDpdkPort> service,
    std::span<const std::string> arguments = {}
) {
    const auto cache_config = shinku::config::CacheConfig::create({
        .max_entries = 4,
        .max_response_bytes = 512,
        .cache_negative = true,
        .max_pending_queries = 4,
        .pending_query_timeout = std::chrono::seconds(1),
    });
    REQUIRE(cache_config.has_value());
    return std::make_unique<shinku::backend::dpdk::DpdkBackend>(
        arguments,
        *cache_config,
        std::move(eal),
        std::move(packet_pool),
        std::move(client),
        std::move(service)
    );
}

} // namespace

TEST_CASE("DPDK packet path closes burst ownership in one quantum") {
    FakeDpdkPort source("fake-client");
    FakeDpdkPort destination("fake-service");
    shinku::backend::dpdk::DpdkPacketForwarder path(source, destination, DnsPacketDirection::Query);
    std::array<rte_mbuf, 4> packets;
    for (rte_mbuf& packet: packets) {
        packet = single_segment_packet();
        source.incoming.push_back(&packet);
    }

    SECTION("complete TX transfers every packet") {
        REQUIRE(path.run().has_value());
        CHECK(source.receive_capacities == std::vector<uint16_t> { 32 });
        CHECK(destination.transmitted.size() == packets.size());
        CHECK(source.freed.empty());
    }

    SECTION("partial TX frees only the unaccepted suffix") {
        destination.tx_limit = 2;
        REQUIRE(path.run().has_value());
        CHECK(destination.transmitted.size() == 2);
        CHECK(source.freed == std::vector<rte_mbuf*> { &packets[2], &packets[3] });
    }

    SECTION("zero TX frees the complete burst") {
        destination.tx_limit = 0;
        REQUIRE(path.run().has_value());
        CHECK(destination.transmitted.empty());
        CHECK(source.freed.size() == packets.size());
    }
}

TEST_CASE("DPDK packet path performs no TX for an empty burst") {
    FakeDpdkPort source("fake-client");
    FakeDpdkPort destination("fake-service");
    shinku::backend::dpdk::DpdkPacketForwarder path(source, destination, DnsPacketDirection::Query);

    REQUIRE(path.run().has_value());
    CHECK(source.receive_capacities == std::vector<uint16_t> { 32 });
    CHECK(destination.transmitted.empty());
    CHECK(source.freed.empty());
}

TEST_CASE("DPDK packet path drops frame-contract violations and continues") {
    FakeDpdkPort source("fake-client");
    FakeDpdkPort destination("fake-service");
    shinku::backend::dpdk::DpdkPacketForwarder path(source, destination, DnsPacketDirection::Query);
    rte_mbuf valid_before = single_segment_packet();
    rte_mbuf multi_segment = single_segment_packet();
    rte_mbuf tail = single_segment_packet();
    multi_segment.nb_segs = 2;
    multi_segment.next = &tail;
    multi_segment.pkt_len += tail.pkt_len;
    rte_mbuf oversized = single_segment_packet(1519);
    rte_mbuf valid_after = single_segment_packet();
    source.incoming = { &valid_before, &multi_segment, &oversized, &valid_after };

    REQUIRE(path.run().has_value());
    CHECK(source.freed == std::vector<rte_mbuf*> { &multi_segment, &oversized });
    CHECK(destination.transmitted == std::vector<rte_mbuf*> { &valid_before, &valid_after });
}

TEST_CASE("DPDK scheduler preserves client service cache pending order") {
    std::vector<int> trace;
    TraceTask client(trace, 1);
    TraceTask service(trace, 2);
    TraceTask cache(trace, 3);
    TraceTask pending(trace, 4);
    shinku::backend::dpdk::DpdkCooperativeScheduler scheduler(client, service, cache, pending);

    REQUIRE(scheduler.run_quantum().has_value());
    CHECK(trace == std::vector<int> { 1, 2, 3, 4 });
}

TEST_CASE("DPDK scheduler returns the first task failure") {
    std::vector<int> trace;
    TraceTask client(trace, 1);
    TraceTask service(trace, 2);
    TraceTask cache(trace, 3);
    TraceTask pending(trace, 4);
    service.result = std::unexpected(BackendError {
        .code = BackendErrorCode::PollFailed,
        .message = "service failed",
        .cause = std::nullopt,
    });
    shinku::backend::dpdk::DpdkCooperativeScheduler scheduler(client, service, cache, pending);

    auto result = scheduler.run_quantum();

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().message == "service failed");
    CHECK(trace == std::vector<int> { 1, 2 });
}

TEST_CASE("DPDK backend forwards native EAL arguments to the EAL component") {
    auto eal = std::make_unique<FakeDpdkEal>();
    auto* eal_trace = eal.get();
    auto pool = std::make_unique<FakeDpdkPacketPool>();
    auto client = std::make_unique<FakeDpdkPort>("fake-client");
    client->configure_result = std::unexpected(DpdkError {
        .operation = "port validation",
        .detail = "configured DPDK Port ID 3 does not exist",
        .cause = std::make_error_code(std::errc::no_such_device),
    });
    auto service = std::make_unique<FakeDpdkPort>("fake-service");
    const std::vector<std::string> arguments { "--no-huge", "--no-pci", "--vdev=net_ring0" };
    BackendRunner runner(make_backend(std::move(eal), std::move(pool), std::move(client), std::move(service), arguments));
    SequencedStopCondition stop({ std::nullopt });

    auto result = runner.run(stop);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StartFailed);
    CHECK(result.error().message.contains("Port ID 3"));
    CHECK(eal_trace->arguments == arguments);
    CHECK(eal_trace->calls == std::vector<std::string> { "initialize", "close" });
}

TEST_CASE("DPDK backend maps EAL initialization failure") {
    auto eal = std::make_unique<FakeDpdkEal>();
    auto* eal_trace = eal.get();
    eal->initialize_result = std::unexpected(DpdkError {
        .operation = "EAL initialization",
        .detail = "fake failure",
        .cause = std::make_error_code(std::errc::permission_denied),
    });
    auto pool = std::make_unique<FakeDpdkPacketPool>();
    auto client = std::make_unique<FakeDpdkPort>("fake-client");
    auto service = std::make_unique<FakeDpdkPort>("fake-service");
    BackendRunner runner(make_backend(std::move(eal), std::move(pool), std::move(client), std::move(service)));
    SequencedStopCondition stop({ std::nullopt });

    auto result = runner.run(stop);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == BackendErrorCode::StartFailed);
    CHECK(eal_trace->calls == std::vector<std::string> { "initialize", "close" });
}

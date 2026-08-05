// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/ebpf_native_session.h"

#include <chrono>
#include <cstddef>
#include <deque>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace shinku::backend::ebpf::testing {

class FakeEbpfNativeSession final: public EbpfNativeSession {
public:
    CapabilityProbeResult privilege_result = true;
    CapabilityProbeResult interface_result = true;
    CapabilityProbeResult arena_result = true;
    std::expected<uint32_t, std::error_code> interface_index_result = 7U;

    std::optional<std::error_code> prepare_error;
    std::expected<void, std::error_code> log_ring_result;
    std::expected<void, std::error_code> packet_ring_result;
    std::deque<std::expected<void, std::error_code>> xdp_results;
    std::deque<std::expected<void, std::error_code>> tcx_results;
    std::deque<std::expected<void, std::error_code>> legacy_tc_results;
    std::deque<std::expected<void, std::error_code>> wait_results;
    std::deque<std::expected<void, std::error_code>> release_results;
    std::deque<std::expected<int, std::error_code>> log_poll_results;
    std::deque<std::expected<int, std::error_code>> packet_poll_results;

    std::string probed_interface;
    std::string indexed_interface;
    std::optional<EbpfSkeletonConfig> configured_skeleton;
    uint32_t attached_ifindex = 0;
    int log_poll_timeout_ms = 0;
    int packet_poll_timeout_ms = 0;
    std::vector<std::chrono::milliseconds> waits;
    std::vector<std::string> calls;
    PacketEventConsumer* packet_consumer = nullptr;
    bool packet_ring_closed = false;

    CapabilityProbeResult has_required_privileges() override {
        calls.emplace_back("probe_privileges");
        return privilege_result;
    }

    CapabilityProbeResult interface_exists(std::string_view iface) override {
        calls.emplace_back("probe_interface");
        probed_interface = iface;
        return interface_result;
    }

    CapabilityProbeResult arena_supported() override {
        calls.emplace_back("probe_arena");
        return arena_result;
    }

    std::expected<uint32_t, std::error_code> interface_index(std::string_view iface) override {
        calls.emplace_back("interface_index");
        indexed_interface = iface;
        return interface_index_result;
    }

    std::expected<EbpfNativeBinding, std::error_code> prepare_skeleton(const EbpfSkeletonConfig& config) override {
        calls.emplace_back("prepare_skeleton");
        configured_skeleton = config;
        if (prepare_error)
            return std::unexpected(*prepare_error);

        constexpr size_t storage_alignment = sizeof(std::max_align_t);
        const size_t storage_words = (config.cache_layout.arena_bytes + storage_alignment - 1) / storage_alignment;
        arena_storage.resize(storage_words);
        auto arena = std::span(reinterpret_cast<std::byte*>(arena_storage.data()), config.cache_layout.arena_bytes);
        return EbpfNativeBinding(EbpfNativeStorageBinding(0, arena), EbpfNativePendingBinding(1));
    }

    std::expected<void, std::error_code> create_log_ring() override {
        calls.emplace_back("create_log_ring");
        return log_ring_result;
    }

    std::expected<void, std::error_code> attach_xdp(uint32_t ifindex) override {
        calls.emplace_back("attach_xdp");
        attached_ifindex = ifindex;
        return pop_or_success(xdp_results);
    }

    std::expected<void, std::error_code> attach_tcx(uint32_t ifindex) override {
        calls.emplace_back("attach_tcx");
        attached_ifindex = ifindex;
        return pop_or_success(tcx_results);
    }

    std::expected<void, std::error_code> attach_legacy_tc(uint32_t ifindex) override {
        calls.emplace_back("attach_legacy_tc");
        attached_ifindex = ifindex;
        return pop_or_success(legacy_tc_results);
    }

    std::expected<void, std::error_code> create_packet_ring(PacketEventConsumer& consumer) override {
        calls.emplace_back("create_packet_ring");
        packet_consumer = &consumer;
        return packet_ring_result;
    }

    void close_packet_ring() noexcept override {
        calls.emplace_back("close_packet_ring");
        packet_consumer = nullptr;
        packet_ring_closed = true;
    }

    void emit_packet_event(std::span<const std::byte> sample) noexcept {
        if (packet_consumer != nullptr)
            packet_consumer->consume(sample);
    }

    std::expected<int, std::error_code> poll_log_ring(int timeout_ms) override {
        calls.emplace_back("poll_log_ring");
        log_poll_timeout_ms = timeout_ms;
        return pop_or_value(log_poll_results, 0);
    }

    std::expected<int, std::error_code> poll_packet_ring(int timeout_ms) override {
        calls.emplace_back("poll_packet_ring");
        packet_poll_timeout_ms = timeout_ms;
        return pop_or_value(packet_poll_results, 0);
    }

    std::expected<void, std::error_code> wait_for(std::chrono::milliseconds duration) override {
        calls.emplace_back("wait_for");
        waits.emplace_back(duration);
        return pop_or_success(wait_results);
    }

    std::expected<void, std::error_code> release() override {
        calls.emplace_back("release");
        return pop_or_success(release_results);
    }

private:
    std::vector<std::max_align_t> arena_storage;

    static std::expected<void, std::error_code> pop_or_success(std::deque<std::expected<void, std::error_code>>& results
    ) {
        if (results.empty())
            return {};
        auto result = results.front();
        results.pop_front();
        return result;
    }

    static std::expected<int, std::error_code>
    pop_or_value(std::deque<std::expected<int, std::error_code>>& results, int fallback) {
        if (results.empty())
            return fallback;
        auto result = results.front();
        results.pop_front();
        return result;
    }
};

} // namespace shinku::backend::ebpf::testing

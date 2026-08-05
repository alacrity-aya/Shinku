// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/cache/ebpf_native_binding.h"
#include "backend/ebpf/cache/ebpf_skeleton_config.h"
#include "backend/ebpf/packet_event_consumer.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <string_view>
#include <system_error>

namespace shinku::backend::ebpf {

using CapabilityProbeResult = std::expected<bool, std::error_code>;
class EbpfNativeSession {
public:
    virtual ~EbpfNativeSession() = default;

    EbpfNativeSession(const EbpfNativeSession&) = delete;
    EbpfNativeSession& operator=(const EbpfNativeSession&) = delete;
    EbpfNativeSession(EbpfNativeSession&&) = delete;
    EbpfNativeSession& operator=(EbpfNativeSession&&) = delete;

    [[nodiscard]] virtual CapabilityProbeResult has_required_privileges() = 0;
    [[nodiscard]] virtual CapabilityProbeResult interface_exists(std::string_view iface) = 0;
    [[nodiscard]] virtual CapabilityProbeResult arena_supported() = 0;
    [[nodiscard]] virtual std::expected<uint32_t, std::error_code> interface_index(std::string_view iface) = 0;

    [[nodiscard]] virtual std::expected<EbpfNativeBinding, std::error_code>
    prepare_skeleton(const EbpfSkeletonConfig& config) = 0;
    [[nodiscard]] virtual std::expected<void, std::error_code> create_log_ring() = 0;
    [[nodiscard]] virtual std::expected<void, std::error_code> attach_xdp(uint32_t ifindex) = 0;
    [[nodiscard]] virtual std::expected<void, std::error_code> attach_tcx(uint32_t ifindex) = 0;
    [[nodiscard]] virtual std::expected<void, std::error_code> attach_legacy_tc(uint32_t ifindex) = 0;
    [[nodiscard]] virtual std::expected<void, std::error_code> create_packet_ring(PacketEventConsumer& consumer) = 0;
    virtual void close_packet_ring() noexcept = 0;

    [[nodiscard]] virtual std::expected<int, std::error_code> poll_log_ring(int timeout_ms) = 0;
    [[nodiscard]] virtual std::expected<int, std::error_code> poll_packet_ring(int timeout_ms) = 0;
    [[nodiscard]] virtual std::expected<void, std::error_code> wait_for(std::chrono::milliseconds duration) = 0;

    [[nodiscard]] virtual std::expected<void, std::error_code> release() = 0;

protected:
    EbpfNativeSession() = default;
};

class ProductionEbpfNativeSession final: public EbpfNativeSession {
public:
    ProductionEbpfNativeSession();
    ~ProductionEbpfNativeSession() override;

    [[nodiscard]] CapabilityProbeResult has_required_privileges() override;
    [[nodiscard]] CapabilityProbeResult interface_exists(std::string_view iface) override;
    [[nodiscard]] CapabilityProbeResult arena_supported() override;
    [[nodiscard]] std::expected<uint32_t, std::error_code> interface_index(std::string_view iface) override;
    [[nodiscard]] std::expected<EbpfNativeBinding, std::error_code> prepare_skeleton(const EbpfSkeletonConfig& config
    ) override;
    [[nodiscard]] std::expected<void, std::error_code> create_log_ring() override;
    [[nodiscard]] std::expected<void, std::error_code> attach_xdp(uint32_t ifindex) override;
    [[nodiscard]] std::expected<void, std::error_code> attach_tcx(uint32_t ifindex) override;
    [[nodiscard]] std::expected<void, std::error_code> attach_legacy_tc(uint32_t ifindex) override;
    [[nodiscard]] std::expected<void, std::error_code> create_packet_ring(PacketEventConsumer& consumer) override;
    void close_packet_ring() noexcept override;
    [[nodiscard]] std::expected<int, std::error_code> poll_log_ring(int timeout_ms) override;
    [[nodiscard]] std::expected<int, std::error_code> poll_packet_ring(int timeout_ms) override;
    [[nodiscard]] std::expected<void, std::error_code> wait_for(std::chrono::milliseconds duration) override;
    [[nodiscard]] std::expected<void, std::error_code> release() override;

private:
    struct NativeResources;
    std::unique_ptr<NativeResources> resources_;
};

} // namespace shinku::backend::ebpf

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

/// Result of a capability probe: true if supported, false if not, or an error.
using CapabilityProbeResult = std::expected<bool, std::error_code>;

/**
 * @brief Abstract libbpf session owning the BPF programs, maps, and rings.
 *
 * The session is the seam between the backend and libbpf so that tests can
 * substitute a fake session without linking against libbpf. It exposes
 * capability probes, skeleton preparation, attach/detach of the XDP and TC
 * programs, ring creation/polling, and final release of all BPF resources.
 */
class EbpfNativeSession {
public:
    virtual ~EbpfNativeSession() = default;

    EbpfNativeSession(const EbpfNativeSession&) = delete;
    EbpfNativeSession& operator=(const EbpfNativeSession&) = delete;
    EbpfNativeSession(EbpfNativeSession&&) = delete;
    EbpfNativeSession& operator=(EbpfNativeSession&&) = delete;

    /// @brief Probe whether the process holds the privileges required to load/attach BPF.
    [[nodiscard]] virtual CapabilityProbeResult has_required_privileges() = 0;
    /// @brief Probe whether the network interface @p iface exists.
    [[nodiscard]] virtual CapabilityProbeResult interface_exists(std::string_view iface) = 0;
    /// @brief Probe whether the kernel supports BPF arena (required for the cache map).
    [[nodiscard]] virtual CapabilityProbeResult arena_supported() = 0;
    /// @brief Resolve @p iface to its kernel interface index.
    [[nodiscard]] virtual std::expected<uint32_t, std::error_code> interface_index(std::string_view iface) = 0;

    /// @brief Open and prepare the BPF skeleton from @p config (does not attach).
    [[nodiscard]] virtual std::expected<EbpfNativeBinding, std::error_code>
    prepare_skeleton(const EbpfSkeletonConfig& config) = 0;
    /// @brief Create the BPF log ring buffer.
    [[nodiscard]] virtual std::expected<void, std::error_code> create_log_ring() = 0;
    /// @brief Attach the XDP program to interface @p ifindex.
    [[nodiscard]] virtual std::expected<void, std::error_code> attach_xdp(uint32_t ifindex) = 0;
    /// @brief Attach the TCX program to interface @p ifindex.
    [[nodiscard]] virtual std::expected<void, std::error_code> attach_tcx(uint32_t ifindex) = 0;
    /// @brief Attach the legacy TC program to interface @p ifindex (fallback path).
    [[nodiscard]] virtual std::expected<void, std::error_code> attach_legacy_tc(uint32_t ifindex) = 0;
    /// @brief Create the packet ring buffer, forwarding samples to @p consumer.
    [[nodiscard]] virtual std::expected<void, std::error_code> create_packet_ring(PacketEventConsumer& consumer) = 0;
    /// @brief Close and detach the packet ring buffer.
    virtual void close_packet_ring() noexcept = 0;

    /// @brief Poll the log ring buffer; @p _ is a reserved argument.
    [[nodiscard]] virtual std::expected<int, std::error_code> poll_log_ring(int _) = 0;
    /// @brief Poll the packet ring buffer, blocking up to @p timeout_ms for events.
    [[nodiscard]] virtual std::expected<int, std::error_code> poll_packet_ring(int timeout_ms) = 0;
    /// @brief Block for @p duration, used to pace the poll loop.
    [[nodiscard]] virtual std::expected<void, std::error_code> wait_for(std::chrono::milliseconds duration) = 0;

    /// @brief Release all BPF resources owned by this session.
    [[nodiscard]] virtual std::expected<void, std::error_code> release() = 0;

protected:
    EbpfNativeSession() = default;
};

/// @brief Production @ref EbpfNativeSession backed by real libbpf calls.
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
    [[nodiscard]] std::expected<int, std::error_code> poll_log_ring(int _) override;
    [[nodiscard]] std::expected<int, std::error_code> poll_packet_ring(int timeout_ms) override;
    [[nodiscard]] std::expected<void, std::error_code> wait_for(std::chrono::milliseconds duration) override;
    [[nodiscard]] std::expected<void, std::error_code> release() override;

private:
    struct NativeResources;
    std::unique_ptr<NativeResources> resources_; ///< Pimpl holding the libbpf object handles.
};

} // namespace shinku::backend::ebpf

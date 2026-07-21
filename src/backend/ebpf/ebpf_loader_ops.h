// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "ebpf_loader_config.h"

#include <expected>
#include <string_view>
#include <system_error>

struct bpf_ctx;

namespace shinku::backend::ebpf {

using CapabilityProbeResult = std::expected<bool, std::error_code>;

struct EbpfLoaderOps {
    CapabilityProbeResult (*has_required_privileges)(void* context);
    CapabilityProbeResult (*interface_exists)(void* context, std::string_view iface);
    CapabilityProbeResult (*arena_supported)(void* context);
    int (*setup)(void* context, bpf_ctx* bpf_context, const EbpfLoaderConfig& config);
    int (*start_cleanup_thread)(void* context, bpf_ctx* bpf_context, uint32_t interval_ms);
    int (*poll_log_ring)(void* context, bpf_ctx* bpf_context, int timeout_ms);
    int (*poll_packet_ring)(void* context, bpf_ctx* bpf_context, int timeout_ms);
    void (*cleanup)(void* context, bpf_ctx* bpf_context);
};

[[nodiscard]] const EbpfLoaderOps& production_ebpf_loader_ops() noexcept;

} // namespace shinku::backend::ebpf

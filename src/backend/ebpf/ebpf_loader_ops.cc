// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/ebpf_loader_ops.h"

#include "backend/ebpf/ebpf_loader_config.h"
#include "bpf_log.h"
#include "constants.h"
#include "core/loader.h"

#include <bpf/libbpf.h>
#include <cerrno>
#include <cstdint>
#include <expected>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <net/if.h>
#include <string>
#include <string_view>
#include <sys/capability.h>
#include <system_error>
#include <unistd.h>

namespace shinku::backend::ebpf {
namespace {

std::error_code current_system_error() {
    return { errno == 0 ? EIO : errno, std::generic_category() };
}

CapabilityProbeResult effective_capability_is_set(cap_t capabilities, cap_value_t capability) {
    cap_flag_value_t value = CAP_CLEAR;
    if (cap_get_flag(capabilities, capability, CAP_EFFECTIVE, &value) != 0)
        return std::unexpected(current_system_error());
    return value == CAP_SET;
}

CapabilityProbeResult has_required_privileges([[maybe_unused]] void* context) {
    if (geteuid() == 0)
        return true;
    if (!CAP_IS_SUPPORTED(CAP_BPF))
        return false;

    cap_t capabilities = cap_get_proc();
    if (capabilities == nullptr)
        return std::unexpected(current_system_error());

    auto has_bpf = effective_capability_is_set(capabilities, CAP_BPF);
    auto has_net_admin = effective_capability_is_set(capabilities, CAP_NET_ADMIN);
    auto has_sys_admin = effective_capability_is_set(capabilities, CAP_SYS_ADMIN);

    const int free_result = cap_free(capabilities);
    if (!has_bpf)
        return std::unexpected(has_bpf.error());
    if (!has_net_admin)
        return std::unexpected(has_net_admin.error());
    if (!has_sys_admin)
        return std::unexpected(has_sys_admin.error());
    if (free_result != 0)
        return std::unexpected(current_system_error());

    return *has_bpf && *has_net_admin && *has_sys_admin;
}

CapabilityProbeResult interface_exists([[maybe_unused]] void* context, std::string_view iface) {
    errno = 0;
    const std::string interface_name(iface);
    if (if_nametoindex(interface_name.c_str()) != 0)
        return true;
    if (errno == 0 || errno == ENODEV || errno == ENXIO || errno == ENOENT)
        return false;
    return std::unexpected(current_system_error());
}

CapabilityProbeResult arena_supported([[maybe_unused]] void* context) {
    const int result = libbpf_probe_bpf_map_type(BPF_MAP_TYPE_ARENA, nullptr);
    if (result > 0)
        return true;
    if (result == 0)
        return false;
    return std::unexpected(std::error_code(-result, std::generic_category()));
}

int setup([[maybe_unused]] void* context, bpf_ctx* bpf_context, const EbpfLoaderConfig& config) {
    const env loader_env = {
        .interface = config.iface.c_str(),
        .log_level = LOG_INFO,
        .arena_pages = config.arena_pages,
        .cleanup_interval_ms = config.cleanup_interval_ms,
        .admission_enabled = 1,
        .pressure_mode = 1,
        .admission_min_ttl = 0,
        .admission_dampen_window_ms = 2000,
        .hot_threshold = 3,
        .freq_width = 4096,
        .freq_epoch_ops = CACHE_MAP_MAX_ENTRIES * 10,
    };
    return loader_setup_bpf(bpf_context, &loader_env);
}

int start_cleanup_thread([[maybe_unused]] void* context, bpf_ctx* bpf_context, uint32_t interval_ms) {
    return loader_start_cleanup_thread(bpf_context, interval_ms);
}

int poll_log_ring([[maybe_unused]] void* context, bpf_ctx* bpf_context, int timeout_ms) {
    return loader_dump_bpf_log(bpf_context, timeout_ms);
}

int poll_packet_ring([[maybe_unused]] void* context, bpf_ctx* bpf_context, int timeout_ms) {
    return loader_poll_pkt_ring(bpf_context, timeout_ms);
}

void cleanup([[maybe_unused]] void* context, bpf_ctx* bpf_context) {
    loader_cleanup_bpf(bpf_context);
}

const EbpfLoaderOps kProductionOps = {
    .has_required_privileges = has_required_privileges,
    .interface_exists = interface_exists,
    .arena_supported = arena_supported,
    .setup = setup,
    .start_cleanup_thread = start_cleanup_thread,
    .poll_log_ring = poll_log_ring,
    .poll_packet_ring = poll_packet_ring,
    .cleanup = cleanup,
};

} // namespace

const EbpfLoaderOps& production_ebpf_loader_ops() noexcept {
    return kProductionOps;
}

} // namespace shinku::backend::ebpf

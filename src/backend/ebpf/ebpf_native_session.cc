// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/ebpf_native_session.h"

#include "bpf_log.h"
#include "constants.h"
#include "core/loader_cache_bridge.h"

#include "cache.skel.h"

#include <array>
#include <bpf/libbpf.h>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <expected>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <memory>
#include <net/if.h>
#include <string>
#include <string_view>
#include <sys/capability.h>
#include <system_error>
#include <thread>
#include <unistd.h>

namespace shinku::backend::ebpf {
namespace {

std::unexpected<std::error_code> current_errno_error() {
    const int value = errno;
    if (value == 0)
        return std::unexpected(std::make_error_code(std::errc::io_error));
    return std::unexpected(std::error_code { value, std::generic_category() });
}

std::unexpected<std::error_code> negative_errno_error(int result) {
    if (result >= 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    return std::unexpected(std::error_code { -result, std::generic_category() });
}

std::unexpected<std::error_code> invalid_state_error() {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
}

CapabilityProbeResult effective_capability_is_set(cap_t capabilities, cap_value_t capability) {
    cap_flag_value_t value = CAP_CLEAR;
    if (cap_get_flag(capabilities, capability, CAP_EFFECTIVE, &value) != 0)
        return current_errno_error();
    return value == CAP_SET;
}

// libbpf supplies a printf-style va_list and invokes this callback through a C ABI.
// NOLINTBEGIN(modernize-use-std-print)
int libbpf_print_callback(libbpf_print_level level, const char* format, va_list args) noexcept {
    std::array<char, LOG_TIMESTAMP_LEN> timestamp {};
    const std::time_t now = std::time(nullptr);
    std::tm local_time {};
    localtime_r(&now, &local_time);
    std::strftime(timestamp.data(), timestamp.size(), "%H:%M:%S", &local_time);

    const char* color;
    const char* level_name;
    switch (level) {
        case LIBBPF_WARN:
            color = COL_YELLOW;
            level_name = "WARN";
            break;
        case LIBBPF_INFO:
            color = COL_GREEN;
            level_name = "INFO";
            break;
        case LIBBPF_DEBUG:
            return 0;
        default:
            color = COL_RED;
            level_name = "ERROR";
            break;
    }

    std::fprintf(stderr, "%s[%s] [%s] ", color, timestamp.data(), level_name);
    const int result = std::vfprintf(stderr, format, args);
    std::fprintf(stderr, "%s", COL_RESET);
    return result;
}
// NOLINTEND(modernize-use-std-print)

} // namespace

struct ProductionEbpfNativeSession::NativeResources {
    cache_bpf* skeleton = nullptr;
    loader_cache_bridge bridge {};
    bool bridge_ready = false;
    bpf_link* xdp = nullptr;
    bpf_link* tcx = nullptr;
    bpf_tc_hook legacy_hook {};
    bpf_tc_opts legacy_opts {};
    bool legacy_attached = false;
    bool owns_clsact = false;
    ring_buffer* log_ring = nullptr;
    ring_buffer* packet_ring = nullptr;
    log_options log_config {
        .min_level = LOG_INFO,
        .show_timestamp = true,
        .use_color = true,
    };
};

ProductionEbpfNativeSession::ProductionEbpfNativeSession(): resources_(std::make_unique<NativeResources>()) {}

ProductionEbpfNativeSession::~ProductionEbpfNativeSession() {
    [[maybe_unused]] auto result = release();
}

CapabilityProbeResult ProductionEbpfNativeSession::has_required_privileges() {
    if (geteuid() == 0)
        return true;
    if (!CAP_IS_SUPPORTED(CAP_BPF))
        return false;

    cap_t capabilities = cap_get_proc();
    if (capabilities == nullptr)
        return current_errno_error();

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
        return current_errno_error();
    return *has_bpf && *has_net_admin && *has_sys_admin;
}

CapabilityProbeResult ProductionEbpfNativeSession::interface_exists(std::string_view iface) {
    const std::string name(iface);
    errno = 0;
    if (if_nametoindex(name.c_str()) != 0)
        return true;
    if (errno == 0 || errno == ENODEV || errno == ENXIO || errno == ENOENT)
        return false;
    return current_errno_error();
}

CapabilityProbeResult ProductionEbpfNativeSession::arena_supported() {
    const int result = libbpf_probe_bpf_map_type(BPF_MAP_TYPE_ARENA, nullptr);
    if (result == 1)
        return true;
    if (result == 0)
        return false;
    return negative_errno_error(result);
}

std::expected<uint32_t, std::error_code> ProductionEbpfNativeSession::interface_index(std::string_view iface) {
    const std::string name(iface);
    errno = 0;
    const unsigned int index = if_nametoindex(name.c_str());
    if (index != 0)
        return index;
    return current_errno_error();
}

std::expected<void, std::error_code> ProductionEbpfNativeSession::prepare_skeleton(uint32_t arena_pages) {
    libbpf_set_print(libbpf_print_callback);
    errno = 0;
    resources_->skeleton = cache_bpf__open();
    if (resources_->skeleton == nullptr)
        return current_errno_error();
    if (resources_->skeleton->maps.arena == nullptr || resources_->skeleton->maps.rb_pkt == nullptr
        || resources_->skeleton->progs.xdp_rx == nullptr || resources_->skeleton->progs.tc_tx == nullptr)
        return invalid_state_error();
#if SHINKU_BPF_LOG_ENABLED
    if (resources_->skeleton->maps._rb_log == nullptr)
        return invalid_state_error();
#endif

    int result = bpf_map__set_max_entries(resources_->skeleton->maps.arena, arena_pages);
    if (result != 0)
        return negative_errno_error(result);

    bpf_program__set_autoattach(resources_->skeleton->progs.xdp_rx, false);
    bpf_program__set_autoattach(resources_->skeleton->progs.tc_tx, false);

    result = cache_bpf__load(resources_->skeleton);
    if (result != 0)
        return negative_errno_error(result);
    result = cache_bpf__attach(resources_->skeleton);
    if (result != 0)
        return negative_errno_error(result);
    return {};
}

std::expected<void, std::error_code> ProductionEbpfNativeSession::create_cache_bridge() {
    const int result = loader_cache_bridge_init(
        &resources_->bridge,
        resources_->skeleton,
        1,
        1,
        0,
        2000,
        3,
        4096,
        CACHE_MAP_MAX_ENTRIES * 10
    );
    if (result != 0)
        return negative_errno_error(result);
    resources_->bridge_ready = true;
    return {};
}

std::expected<void, std::error_code> ProductionEbpfNativeSession::create_log_ring() {
#if SHINKU_BPF_LOG_ENABLED
    errno = 0;
    resources_->log_ring = ring_buffer__new(
        bpf_map__fd(resources_->skeleton->maps._rb_log),
        print_bpf_log,
        &resources_->log_config,
        nullptr
    );
    if (resources_->log_ring == nullptr)
        return current_errno_error();
#endif
    return {};
}

std::expected<void, std::error_code> ProductionEbpfNativeSession::attach_xdp(uint32_t ifindex) {
    errno = 0;
    bpf_link* link = bpf_program__attach_xdp(resources_->skeleton->progs.xdp_rx, static_cast<int>(ifindex));
    if (link == nullptr)
        return current_errno_error();
    resources_->xdp = link;
    return {};
}

std::expected<void, std::error_code> ProductionEbpfNativeSession::attach_tcx(uint32_t ifindex) {
    errno = 0;
    bpf_link* link = bpf_program__attach_tcx(resources_->skeleton->progs.tc_tx, static_cast<int>(ifindex), nullptr);
    if (link == nullptr)
        return current_errno_error();
    resources_->tcx = link;
    return {};
}

std::expected<void, std::error_code> ProductionEbpfNativeSession::attach_legacy_tc(uint32_t ifindex) {
    bpf_tc_hook hook = resources_->owns_clsact ? resources_->legacy_hook : bpf_tc_hook {};
    bool owns_clsact = resources_->owns_clsact;
    if (!owns_clsact) {
        hook.sz = sizeof(bpf_tc_hook);
        hook.ifindex = static_cast<int>(ifindex);
        hook.attach_point = BPF_TC_EGRESS;
        const int create_result = bpf_tc_hook_create(&hook);
        if (create_result != 0 && create_result != -EEXIST)
            return negative_errno_error(create_result);
        owns_clsact = create_result == 0;
    }

    bpf_tc_opts opts {};
    opts.sz = sizeof(bpf_tc_opts);
    opts.prog_fd = bpf_program__fd(resources_->skeleton->progs.tc_tx);
    opts.handle = 1;
    opts.priority = 1;
    const int result = bpf_tc_attach(&hook, &opts);
    if (result != 0) {
        if (owns_clsact) {
            if (bpf_tc_hook_destroy(&hook) != 0) {
                resources_->legacy_hook = hook;
                resources_->legacy_opts = opts;
                resources_->owns_clsact = true;
            } else {
                resources_->legacy_hook = {};
                resources_->legacy_opts = {};
                resources_->owns_clsact = false;
            }
        }
        return negative_errno_error(result);
    }

    resources_->legacy_hook = hook;
    resources_->legacy_opts = opts;
    resources_->legacy_attached = true;
    resources_->owns_clsact = owns_clsact;
    return {};
}

std::expected<void, std::error_code> ProductionEbpfNativeSession::create_packet_ring() {
    errno = 0;
    resources_->packet_ring = ring_buffer__new(
        bpf_map__fd(resources_->skeleton->maps.rb_pkt),
        loader_cache_bridge_packet_callback,
        &resources_->bridge,
        nullptr
    );
    if (resources_->packet_ring == nullptr)
        return current_errno_error();
    return {};
}

std::expected<int, std::error_code> ProductionEbpfNativeSession::poll_log_ring([[maybe_unused]] int timeout_ms) {
#if SHINKU_BPF_LOG_ENABLED
    const int result = ring_buffer__poll(resources_->log_ring, timeout_ms);
    if (result < 0)
        return negative_errno_error(result);
    return result;
#else
    return 0;
#endif
}

std::expected<int, std::error_code> ProductionEbpfNativeSession::poll_packet_ring(int timeout_ms) {
    const int result = ring_buffer__poll(resources_->packet_ring, timeout_ms);
    if (result < 0)
        return negative_errno_error(result);
    return result;
}

std::expected<int, std::error_code> ProductionEbpfNativeSession::cleanup_expired_entries() {
    const int result = loader_cache_bridge_cleanup(&resources_->bridge);
    if (result < 0)
        return negative_errno_error(result);
    return result;
}

std::expected<void, std::error_code> ProductionEbpfNativeSession::wait_for(std::chrono::milliseconds duration) {
    std::this_thread::sleep_for(duration);
    return {};
}

std::expected<void, std::error_code> ProductionEbpfNativeSession::release() {
    std::expected<void, std::error_code> release_result;
    const auto record = [&release_result](int result) {
        if (result != 0 && release_result)
            release_result = negative_errno_error(result);
    };

    if (resources_->packet_ring != nullptr) {
        ring_buffer__free(resources_->packet_ring);
        resources_->packet_ring = nullptr;
    }
    if (resources_->log_ring != nullptr) {
        ring_buffer__free(resources_->log_ring);
        resources_->log_ring = nullptr;
    }
    if (resources_->xdp != nullptr) {
        bpf_link* link = resources_->xdp;
        resources_->xdp = nullptr;
        record(bpf_link__destroy(link));
    }
    if (resources_->tcx != nullptr) {
        bpf_link* link = resources_->tcx;
        resources_->tcx = nullptr;
        record(bpf_link__destroy(link));
    }
    if (resources_->legacy_attached) {
        const int result = bpf_tc_detach(&resources_->legacy_hook, &resources_->legacy_opts);
        record(result);
        if (result == 0)
            resources_->legacy_attached = false;
    }
    if (!resources_->legacy_attached && resources_->owns_clsact) {
        const int result = bpf_tc_hook_destroy(&resources_->legacy_hook);
        record(result);
        if (result == 0)
            resources_->owns_clsact = false;
    }
    if (!resources_->legacy_attached && !resources_->owns_clsact) {
        resources_->legacy_hook = {};
        resources_->legacy_opts = {};
    }
    if (resources_->bridge_ready) {
        loader_cache_bridge_destroy(&resources_->bridge);
        resources_->bridge_ready = false;
    }
    if (resources_->skeleton != nullptr && !resources_->legacy_attached && !resources_->owns_clsact) {
        cache_bpf__destroy(resources_->skeleton);
        resources_->skeleton = nullptr;
    }

    return release_result;
}

} // namespace shinku::backend::ebpf

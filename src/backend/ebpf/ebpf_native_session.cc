// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/ebpf_native_session.h"

#include "bpf_log.h"

#include "cache.skel.h"

#include <array>
#include <bpf/libbpf.h>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <expected>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <memory>
#include <net/if.h>
#include <poll.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/capability.h>
#include <system_error>
#include <thread>
#include <unistd.h>

namespace shinku::backend::ebpf {
namespace {

/// Build an unexpected error from the current errno; a zero errno is reported as a generic I/O error.
std::unexpected<std::error_code> current_errno_error() {
    const int value = errno;
    if (value == 0)
        return std::unexpected(std::make_error_code(std::errc::io_error));
    return std::unexpected(std::error_code { value, std::generic_category() });
}

/// Convert a libbpf-style negative-errno result into an unexpected error_code (e.g. -EACCES -> EACCES).
std::unexpected<std::error_code> negative_errno_error(int result) {
    return std::unexpected(std::error_code { -result, std::generic_category() });
}

/// A zeroed legacy TC hook defaulting to the egress attach point; used before any real hook is created.
bpf_tc_hook empty_legacy_tc_hook() noexcept {
    return bpf_tc_hook {
        .sz = sizeof(bpf_tc_hook),
        .ifindex = 0,
        .attach_point = BPF_TC_EGRESS,
        .parent = 0,
        .handle = 0,
        .qdisc = nullptr,
    };
}

/// Derive detach options from the recorded attach opts; legacy TC detach needs the original handle and priority.
bpf_tc_opts legacy_tc_detach_opts(const bpf_tc_opts& attached_opts) noexcept {
    bpf_tc_opts opts {};
    opts.sz = sizeof(bpf_tc_opts);
    opts.handle = attached_opts.handle;
    opts.priority = attached_opts.priority;
    return opts;
}

/// Destroy the clsact qdisc this session created, covering both ingress and egress attach points.
int destroy_owned_clsact(const bpf_tc_hook& legacy_hook) noexcept {
    bpf_tc_hook qdisc_hook = legacy_hook;
    qdisc_hook.attach_point = static_cast<bpf_tc_attach_point>(BPF_TC_INGRESS | BPF_TC_EGRESS);
    return bpf_tc_hook_destroy(&qdisc_hook);
}

/// libbpf ring callback trampoline: re-cast @p context to the consumer and forward the sample as a byte span.
int packet_event_trampoline(void* context, void* data, size_t size) noexcept {
    static_cast<PacketEventConsumer*>(context)->consume(std::span(static_cast<const std::byte*>(data), size));
    return 0;
}

/// Return whether @p capability is set in the effective set of @p capabilities, or an errno error.
CapabilityProbeResult effective_capability_is_set(cap_t capabilities, cap_value_t capability) {
    cap_flag_value_t value = CAP_CLEAR;
    if (cap_get_flag(capabilities, capability, CAP_EFFECTIVE, &value) != 0)
        return current_errno_error();
    return value == CAP_SET;
}

/// libbpf supplies a printf-style va_list and invokes this callback through a C ABI.
// NOLINTBEGIN(modernize-use-std-print)
int libbpf_print_callback(libbpf_print_level level, const char* format, va_list args) noexcept {
    std::array<char, 16> timestamp {};
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

/// Pimpl bundle holding every libbpf object handle owned by one native session.
struct ProductionEbpfNativeSession::NativeResources {
    cache_bpf* skeleton = nullptr; ///< Opened/loaded BPF skeleton, or null once destroyed.
    bpf_link* xdp = nullptr; ///< XDP link handle, or null when not attached.
    bpf_link* tcx = nullptr; ///< TCX link handle, or null when not attached.
    bpf_tc_hook legacy_hook = empty_legacy_tc_hook(); ///< Legacy TC hook used by the fallback attach path.
    bpf_tc_opts legacy_opts {}; ///< Legacy TC attach options (handle/priority) needed to detach.
    bool legacy_attached = false; ///< Whether the legacy TC program is currently attached.
    bool owns_clsact = false; ///< Whether this session created the clsact qdisc and must destroy it.
    ring_buffer* log_ring = nullptr; ///< BPF log ring buffer, or null when logging is disabled.
    ring_buffer* packet_ring = nullptr; ///< Packet event ring buffer.
    PacketEventConsumer* packet_consumer = nullptr; ///< Consumer that packet ring samples are forwarded to.
    log_options log_config { ///< Formatting options passed to the log ring callback.
        .min_level = LOG_INFO,
        .show_timestamp = true,
        .use_color = true,
    };
};

/// Start with an empty NativeResources bundle; all libbpf objects are created lazily.
ProductionEbpfNativeSession::ProductionEbpfNativeSession(): resources_(std::make_unique<NativeResources>()) {}

/// RAII teardown: release() runs so an unwinding session never leaks BPF objects; its result is discarded.
ProductionEbpfNativeSession::~ProductionEbpfNativeSession() {
    auto _ = release();
}

/// Effective root short-circuits to true; otherwise all of CAP_BPF, CAP_NET_ADMIN, and CAP_SYS_ADMIN must be effective.
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

/// Resolve via if_nametoindex; ENOENT/ENODEV/ENXIO (or a missing errno) mean the interface does not exist.
CapabilityProbeResult ProductionEbpfNativeSession::interface_exists(std::string_view iface) {
    const std::string name(iface);
    errno = 0;
    if (if_nametoindex(name.c_str()) != 0)
        return true;
    if (errno == 0 || errno == ENODEV || errno == ENXIO || errno == ENOENT)
        return false;
    return current_errno_error();
}

/// Ask libbpf whether BPF_MAP_TYPE_ARENA is probeable on this kernel (1 = supported, 0 = not).
CapabilityProbeResult ProductionEbpfNativeSession::arena_supported() {
    const int result = libbpf_probe_bpf_map_type(BPF_MAP_TYPE_ARENA, nullptr);
    if (result == 1)
        return true;
    if (result == 0)
        return false;
    return negative_errno_error(result);
}

/// Resolve the interface name via if_nametoindex, surfacing any errno as the error.
std::expected<uint32_t, std::error_code> ProductionEbpfNativeSession::interface_index(std::string_view iface) {
    const std::string name(iface);
    errno = 0;
    const unsigned int index = if_nametoindex(name.c_str());
    if (index != 0)
        return index;
    return current_errno_error();
}

/**
 * Open the skeleton, bake @p config into its rodata and map sizes, then load and
 * attach it. Autoattach is disabled for xdp_rx and tc_tx so they are attached
 * explicitly later; the returned binding exposes the cache map and arena slots.
 */
std::expected<EbpfNativeBinding, std::error_code>
ProductionEbpfNativeSession::prepare_skeleton(const EbpfSkeletonConfig& config) {
    libbpf_set_print(libbpf_print_callback);
    errno = 0;
    resources_->skeleton = cache_bpf__open();
    if (resources_->skeleton == nullptr)
        return current_errno_error();

    resources_->skeleton->rodata->shinku_config.cache_layout = config.cache_layout.bpf_layout();
    resources_->skeleton->rodata->shinku_config.secret = config.secret;
    resources_->skeleton->rodata->shinku_config.pending_timeout_ns = config.pending_timeout_ns;

    int result = bpf_map__set_max_entries(resources_->skeleton->maps.arena, config.cache_layout.arena_page_count);
    if (result != 0)
        return negative_errno_error(result);
    result = bpf_map__set_max_entries(resources_->skeleton->maps.cache_map, config.cache_layout.entry_capacity);
    if (result != 0)
        return negative_errno_error(result);
    result = bpf_map__set_max_entries(resources_->skeleton->maps.pending_queries, config.pending_capacity);
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
    return EbpfNativeBinding(
        EbpfNativeStorageBinding(
            bpf_map__fd(resources_->skeleton->maps.cache_map),
            std::as_writable_bytes(std::span(resources_->skeleton->arena->cache_slots, config.cache_layout.arena_bytes))
        ),
        EbpfNativePendingBinding(bpf_map__fd(resources_->skeleton->maps.pending_queries))
    );
}

/// Create the log ring only when BPF logging is compiled in; otherwise a no-op success.
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

/// Attach xdp_rx to @p ifindex and store the returned link so release() can destroy it.
std::expected<void, std::error_code> ProductionEbpfNativeSession::attach_xdp(uint32_t ifindex) {
    errno = 0;
    bpf_link* link = bpf_program__attach_xdp(resources_->skeleton->progs.xdp_rx, static_cast<int>(ifindex));
    if (link == nullptr)
        return current_errno_error();
    resources_->xdp = link;
    return {};
}

/// Attach tc_tx via TCX to @p ifindex and store the returned link for release().
std::expected<void, std::error_code> ProductionEbpfNativeSession::attach_tcx(uint32_t ifindex) {
    errno = 0;
    bpf_link* link = bpf_program__attach_tcx(resources_->skeleton->progs.tc_tx, static_cast<int>(ifindex), nullptr);
    if (link == nullptr)
        return current_errno_error();
    resources_->tcx = link;
    return {};
}

/**
 * Legacy fallback for attach_tcx: create the clsact qdisc when this session does
 * not already own one (EEXIST is tolerated), then attach tc_tx with handle and
 * priority 1. On failure a clsact created here is torn down so nothing leaks;
 * on success the hook and options are recorded for the later detach.
 */
std::expected<void, std::error_code> ProductionEbpfNativeSession::attach_legacy_tc(uint32_t ifindex) {
    bpf_tc_hook hook = resources_->owns_clsact ? resources_->legacy_hook : empty_legacy_tc_hook();
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
            if (destroy_owned_clsact(hook) != 0) {
                resources_->legacy_hook = hook;
                resources_->legacy_opts = opts;
                resources_->owns_clsact = true;
            } else {
                resources_->legacy_hook = empty_legacy_tc_hook();
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

/// Record the consumer, then create the packet ring over the packet map and its callback.
std::expected<void, std::error_code> ProductionEbpfNativeSession::create_packet_ring(PacketEventConsumer& consumer) {
    resources_->packet_consumer = &consumer;
    errno = 0;
    resources_->packet_ring = ring_buffer__new(
        bpf_map__fd(resources_->skeleton->maps.rb_pkt),
        packet_event_trampoline,
        resources_->packet_consumer,
        nullptr
    );
    if (resources_->packet_ring == nullptr)
        return current_errno_error();
    return {};
}

/// Free the packet ring if present and drop the consumer pointer, leaving the session cleanly re-attachable.
void ProductionEbpfNativeSession::close_packet_ring() noexcept {
    if (resources_->packet_ring != nullptr) {
        ring_buffer__free(resources_->packet_ring);
        resources_->packet_ring = nullptr;
    }
    resources_->packet_consumer = nullptr;
}

/// Poll the log ring when BPF logging is compiled in; otherwise a no-op that reports no events.
std::expected<int, std::error_code> ProductionEbpfNativeSession::poll_log_ring(int _) {
#if SHINKU_BPF_LOG_ENABLED
    const int result = ring_buffer__poll(resources_->log_ring, timeout_ms);
    if (result < 0)
        return negative_errno_error(result);
    return result;
#else
    return 0;
#endif
}

/**
 * Drain up to a fixed batch of samples non-blocking; if none arrived, block on
 * the ring's epoll fd for up to @p timeout_ms and drain again once woken.
 */
std::expected<int, std::error_code> ProductionEbpfNativeSession::poll_packet_ring(int timeout_ms) {
    constexpr size_t batch_limit = 64;
    int result = ring_buffer__consume_n(resources_->packet_ring, batch_limit);
    if (result < 0)
        return negative_errno_error(result);
    if (result != 0)
        return result;

    const int epoll_fd = ring_buffer__epoll_fd(resources_->packet_ring);
    if (epoll_fd < 0)
        return negative_errno_error(epoll_fd);
    pollfd descriptor {
        .fd = epoll_fd,
        .events = POLLIN,
        .revents = 0,
    };
    errno = 0;
    const int wait_result = ::poll(&descriptor, 1, timeout_ms);
    if (wait_result < 0)
        return current_errno_error();
    if (wait_result == 0)
        return 0;

    result = ring_buffer__consume_n(resources_->packet_ring, batch_limit);
    if (result < 0)
        return negative_errno_error(result);
    return result;
}

/// Block the caller for @p duration; used to pace the poll loop and back off between attach retries.
std::expected<void, std::error_code> ProductionEbpfNativeSession::wait_for(std::chrono::milliseconds duration) {
    std::this_thread::sleep_for(duration);
    return {};
}

/**
 * Idempotent teardown in reverse bring-up order: packet ring, log ring, XDP
 * link, TCX link, legacy TC detach, the owned clsact qdisc, and finally the
 * skeleton once no legacy attachment still references it. Every object is
 * released even on failure; the first error encountered is reported.
 */
std::expected<void, std::error_code> ProductionEbpfNativeSession::release() {
    std::expected<void, std::error_code> release_result;
    const auto record = [&release_result](int result) {
        if (result != 0 && release_result)
            release_result = negative_errno_error(result);
    };

    close_packet_ring();
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
        const bpf_tc_opts detach_opts = legacy_tc_detach_opts(resources_->legacy_opts);
        const int result = bpf_tc_detach(&resources_->legacy_hook, &detach_opts);
        record(result);
        if (result == 0)
            resources_->legacy_attached = false;
    }
    if (!resources_->legacy_attached && resources_->owns_clsact) {
        const int result = destroy_owned_clsact(resources_->legacy_hook);
        record(result);
        if (result == 0)
            resources_->owns_clsact = false;
    }
    if (!resources_->legacy_attached && !resources_->owns_clsact) {
        resources_->legacy_hook = empty_legacy_tc_hook();
        resources_->legacy_opts = {};
    }
    if (resources_->skeleton != nullptr && !resources_->legacy_attached && !resources_->owns_clsact) {
        cache_bpf__destroy(resources_->skeleton);
        resources_->skeleton = nullptr;
    }

    return release_result;
}

} // namespace shinku::backend::ebpf

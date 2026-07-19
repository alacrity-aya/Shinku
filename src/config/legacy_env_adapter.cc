// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config/legacy_env_adapter.h"

#include "constants.h"

#include <chrono>
#include <limits>
#include <string>

namespace shinku::config {
namespace {

const char* stable_iface_storage(const std::string& iface) {
    static thread_local std::string stored_iface;
    stored_iface = iface;
    return stored_iface.c_str();
}

} // namespace

std::expected<env, ConfigError> to_legacy_env(const Config& config) {
    if (config.backend != BackendKind::Ebpf || !std::holds_alternative<EbpfConfig>(config.backend_config)) {
        return std::unexpected(ConfigError{
            .code = ConfigErrorCode::UnsupportedBackend,
            .path = {},
            .message = "legacy eBPF runtime supports only backend ebpf",
        });
    }

    const auto& ebpf = std::get<EbpfConfig>(config.backend_config);
    if (ebpf.cleanup_interval.count() <= 0 || ebpf.cleanup_interval.count() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(ConfigError{
            .code = ConfigErrorCode::ValidationError,
            .path = {},
            .message = "invalid ebpf.cleanup_interval: legacy runtime interval is out of range",
        });
    }

    env out = {};
    out.interface = stable_iface_storage(ebpf.iface);
    out.log_level = LOG_INFO;
    out.arena_pages = ebpf.arena_pages;
    out.cleanup_interval_ms = static_cast<std::uint32_t>(ebpf.cleanup_interval.count());

    out.metrics_port = 9095;
    out.obs_enabled = 1;
    out.obs_bpf_enabled = 0;
    out.obs_bpf_sample_mask = 0xff;

    out.admission_enabled = 1;
    out.pressure_mode = 1;
    out.admission_min_ttl = 0;
    out.admission_dampen_window_ms = 2000;
    out.hot_threshold = 3;
    out.freq_width = 4096;
    out.freq_epoch_ops = CACHE_MAP_MAX_ENTRIES * 10;

    return out;
}

} // namespace shinku::config

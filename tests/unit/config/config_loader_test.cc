// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config/legacy_env_adapter.h"
#include "config/toml_loader.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace {

int tests_run = 0;
int tests_failed = 0;

class CapturingSink final : public shinku::config::DiagnosticSink {
public:
    void warning(const shinku::config::ConfigWarning& warning) override {
        messages_.push_back("warning: " + warning.message);
    }

    void error(const shinku::config::ConfigError& error) override {
        messages_.push_back("error: " + error.message);
    }

    const std::vector<std::string>& messages() const {
        return messages_;
    }

private:
    std::vector<std::string> messages_;
};

void expect(bool condition, const std::string& message) {
    tests_run++;
    if (!condition) {
        tests_failed++;
        std::cerr << "FAIL: " << message << '\n';
    }
}

std::filesystem::path write_config(std::string_view name, std::string_view body) {
    const auto dir = std::filesystem::temp_directory_path() / "shinku_config_tests";
    std::filesystem::create_directories(dir);
    const auto path = dir / name;
    std::ofstream file(path);
    file << body;
    return path;
}

void valid_ebpf_config_loads_and_adapts_to_legacy_env() {
    const auto path = write_config(
        "valid-ebpf.toml",
        R"(backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 2112
cleanup_interval = "10s"

[cache]
max_entries = 16384
max_response_bytes = 512
cache_negative = true
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    expect(result.has_value(), "valid eBPF config should load");
    expect(result->backend == shinku::config::BackendKind::Ebpf, "backend should be eBPF");
    expect(result->backend_config.index() == 0, "returned Config should retain only selected eBPF config");
    const auto& ebpf = std::get<shinku::config::EbpfConfig>(result->backend_config);
    expect(ebpf.iface == "eth0", "eBPF iface should parse");
    expect(ebpf.arena_pages == 2112, "eBPF arena_pages should parse");
    expect(ebpf.cleanup_interval.count() == 10'000, "10s should parse to 10000ms");
    expect(result->cache.max_entries == 16384, "cache max_entries should parse");
    expect(result->cache.max_response_bytes == 512, "cache max_response_bytes should parse");
    expect(result->cache.cache_negative, "cache_negative should parse");
    expect(sink.messages().empty(), "valid config should not emit diagnostics");

    auto legacy = shinku::config::to_legacy_env(*result);
    expect(legacy.has_value(), "eBPF config should adapt to legacy env");
    expect(std::string(legacy->interface) == "eth0", "legacy env interface should map iface");
    expect(legacy->arena_pages == 2112, "legacy env arena_pages should map");
    expect(legacy->cleanup_interval_ms == 10'000, "legacy cleanup interval should map milliseconds");
}

void valid_dpdk_config_loads_but_legacy_adapter_rejects_it() {
    const auto path = write_config(
        "valid-dpdk.toml",
        R"(backend = "dpdk"

[dpdk]
client_port = 0
server_port = 1

[cache]
max_entries = 1024
max_response_bytes = 512
cache_negative = false
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    expect(result.has_value(), "valid DPDK config should load");
    expect(result->backend == shinku::config::BackendKind::Dpdk, "backend should be DPDK");
    expect(result->backend_config.index() == 1, "returned Config should retain only selected DPDK config");
    const auto& dpdk = std::get<shinku::config::DpdkConfig>(result->backend_config);
    expect(dpdk.client_port == 0, "DPDK client_port should parse");
    expect(dpdk.server_port == 1, "DPDK server_port should parse");

    auto legacy = shinku::config::to_legacy_env(*result);
    expect(!legacy.has_value(), "DPDK config should not adapt to legacy env");
    expect(
        legacy.error().code == shinku::config::ConfigErrorCode::UnsupportedBackend,
        "DPDK legacy adapter failure should be UnsupportedBackend"
    );
}

void unselected_backend_can_be_incomplete_and_is_not_retained() {
    const auto path = write_config(
        "unselected-incomplete.toml",
        R"(backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 2112
cleanup_interval = "100ms"

[dpdk]
client_port = 0

[cache]
max_entries = 1024
max_response_bytes = 512
cache_negative = true
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    expect(result.has_value(), "incomplete unselected backend table should not fail");
    expect(result->backend_config.index() == 0, "unselected backend config should not be retained");
    expect(
        std::get<shinku::config::EbpfConfig>(result->backend_config).cleanup_interval.count() == 100,
        "100ms should parse"
    );
}

void unknown_key_warning_is_emitted_before_first_hard_error() {
    const auto path = write_config(
        "warning-before-error.toml",
        R"(backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 2112
leanup_interval = "10s"

[cache]
max_entries = 1024
max_response_bytes = 512
cache_negative = true
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    expect(!result.has_value(), "missing cleanup_interval should fail");
    expect(
        result.error().code == shinku::config::ConfigErrorCode::SchemaError,
        "missing required key should be SchemaError"
    );
    expect(result.error().path == path, "ConfigError should retain path");
    expect(sink.messages().size() == 2, "warning should be emitted before first hard error");
    expect(
        sink.messages().at(0).find("warning: unknown key ebpf.leanup_interval") != std::string::npos,
        "unknown key warning should include field path"
    );
    expect(
        sink.messages().at(1).find("error: missing required key ebpf.cleanup_interval") != std::string::npos,
        "hard error should include missing field path"
    );
}

void invalid_duration_is_validation_error() {
    const auto path = write_config(
        "bad-duration.toml",
        R"(backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 2112
cleanup_interval = "10h"

[cache]
max_entries = 1024
max_response_bytes = 512
cache_negative = true
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    expect(!result.has_value(), "unsupported duration unit should fail");
    expect(
        result.error().code == shinku::config::ConfigErrorCode::ValidationError,
        "bad duration should be ValidationError"
    );
    expect(
        result.error().message.find("ebpf.cleanup_interval") != std::string::npos,
        "bad duration diagnostic should include field path"
    );
}

void missing_file_maps_to_file_not_found() {
    const auto path = std::filesystem::temp_directory_path() / "shinku_config_tests" / "missing.toml";
    std::filesystem::remove(path);

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    expect(!result.has_value(), "missing file should fail");
    expect(
        result.error().code == shinku::config::ConfigErrorCode::FileNotFound,
        "missing file should map to FileNotFound"
    );
    expect(result.error().path == path, "missing file error should retain path");
    expect(sink.messages().size() == 1, "missing file should emit one error diagnostic");
}

void first_hard_error_stops_validation() {
    const auto path = write_config(
        "first-hard-error.toml",
        R"(backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 64
cleanup_interval = "0s"

[cache]
max_entries = 0
max_response_bytes = 0
cache_negative = true
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    expect(!result.has_value(), "first invalid eBPF field should fail");
    expect(
        result.error().message.find("ebpf.arena_pages") != std::string::npos,
        "first hard error should be arena_pages before later errors"
    );
    expect(sink.messages().size() == 1, "hard validation should stop at first error");
}

void invalid_dpdk_port_pair_fails() {
    const auto path = write_config(
        "bad-dpdk.toml",
        R"(backend = "dpdk"

[dpdk]
client_port = 7
server_port = 7

[cache]
max_entries = 1024
max_response_bytes = 512
cache_negative = true
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    expect(!result.has_value(), "equal DPDK ports should fail");
    expect(
        result.error().code == shinku::config::ConfigErrorCode::ValidationError,
        "equal DPDK ports should be ValidationError"
    );
    expect(
        result.error().message.find("dpdk.server_port") != std::string::npos,
        "equal port diagnostic should include field path"
    );
}

} // namespace

int main() {
    valid_ebpf_config_loads_and_adapts_to_legacy_env();
    valid_dpdk_config_loads_but_legacy_adapter_rejects_it();
    unselected_backend_can_be_incomplete_and_is_not_retained();
    unknown_key_warning_is_emitted_before_first_hard_error();
    invalid_duration_is_validation_error();
    missing_file_maps_to_file_not_found();
    first_hard_error_stops_validation();
    invalid_dpdk_port_pair_fails();

    if (tests_failed != 0) {
        std::cerr << tests_failed << " of " << tests_run << " config tests failed\n";
        return EXIT_FAILURE;
    }

    std::cout << tests_run << " config tests passed\n";
    return EXIT_SUCCESS;
}

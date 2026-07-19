// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config/legacy_env_adapter.h"
#include "config/toml_loader.h"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace {

class CapturingSink final: public shinku::config::DiagnosticSink {
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

std::filesystem::path write_config(std::string_view name, std::string_view body) {
    const auto dir = std::filesystem::temp_directory_path() / "shinku_config_tests";
    std::filesystem::create_directories(dir);
    const auto path = dir / name;
    std::ofstream file(path);
    file << body;
    return path;
}

} // namespace

TEST_CASE("valid eBPF config loads and adapts to legacy env") {
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

    REQUIRE(result.has_value());
    CHECK(result->backend == shinku::config::BackendKind::Ebpf);
    CHECK(result->backend_config.index() == 0);

    const auto& ebpf = std::get<shinku::config::EbpfConfig>(result->backend_config);
    CHECK(ebpf.iface == "eth0");
    CHECK(ebpf.arena_pages == 2112);
    CHECK(ebpf.cleanup_interval.count() == 10'000);
    CHECK(result->cache.max_entries == 16384);
    CHECK(result->cache.max_response_bytes == 512);
    CHECK(result->cache.cache_negative);
    CHECK(sink.messages().empty());

    auto legacy = shinku::config::to_legacy_env(*result);
    REQUIRE(legacy.has_value());
    CHECK(std::string(legacy->interface) == "eth0");
    CHECK(legacy->arena_pages == 2112);
    CHECK(legacy->cleanup_interval_ms == 10'000);
}

TEST_CASE("valid DPDK config loads but legacy adapter rejects it") {
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

    REQUIRE(result.has_value());
    CHECK(result->backend == shinku::config::BackendKind::Dpdk);
    CHECK(result->backend_config.index() == 1);

    const auto& dpdk = std::get<shinku::config::DpdkConfig>(result->backend_config);
    CHECK(dpdk.client_port == 0);
    CHECK(dpdk.server_port == 1);

    auto legacy = shinku::config::to_legacy_env(*result);
    REQUIRE_FALSE(legacy.has_value());
    CHECK(legacy.error().code == shinku::config::ConfigErrorCode::UnsupportedBackend);
}

TEST_CASE("unselected backend can be incomplete and is not retained") {
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

    REQUIRE(result.has_value());
    CHECK(result->backend_config.index() == 0);
    CHECK(std::get<shinku::config::EbpfConfig>(result->backend_config).cleanup_interval.count() == 100);
}

TEST_CASE("unknown key warning is emitted before first hard error") {
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

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::SchemaError);
    CHECK(result.error().path == path);
    REQUIRE(sink.messages().size() == 2);
    CHECK(sink.messages().at(0).find("warning: unknown key ebpf.leanup_interval") != std::string::npos);
    CHECK(sink.messages().at(1).find("error: missing required key ebpf.cleanup_interval") != std::string::npos);
}

TEST_CASE("invalid duration is a validation error") {
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

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::ValidationError);
    CHECK(result.error().message.find("ebpf.cleanup_interval") != std::string::npos);
}

TEST_CASE("missing file maps to FileNotFound") {
    const auto path = std::filesystem::temp_directory_path() / "shinku_config_tests" / "missing.toml";
    std::filesystem::remove(path);

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::FileNotFound);
    CHECK(result.error().path == path);
    REQUIRE(sink.messages().size() == 1);
}

TEST_CASE("first hard error stops validation") {
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

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().message.find("ebpf.arena_pages") != std::string::npos);
    REQUIRE(sink.messages().size() == 1);
}

TEST_CASE("invalid DPDK port pair fails") {
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

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::ValidationError);
    CHECK(result.error().message.find("dpdk.server_port") != std::string::npos);
}

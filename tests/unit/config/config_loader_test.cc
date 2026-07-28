// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config/toml_loader.h"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
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

    [[nodiscard]] const std::vector<std::string>& messages() const {
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

TEST_CASE("valid eBPF config loads") {
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
max_pending_queries = 8192
pending_query_timeout = "2s"
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
    CHECK(ebpf.packet_poll_timeout.count() == 100);
    CHECK(result->cache.max_entries == 16384);
    CHECK(result->cache.max_response_bytes == 512);
    CHECK(result->cache.cache_negative);
    CHECK(result->cache.max_pending_queries == 8192);
    CHECK(result->cache.pending_query_timeout.count() == 2'000);
    CHECK(sink.messages().empty());
}

TEST_CASE("valid DPDK config loads") {
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
max_pending_queries = 256
pending_query_timeout = "100ms"
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
max_pending_queries = 256
pending_query_timeout = "10s"
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
max_pending_queries = 256
pending_query_timeout = "2s"
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
max_pending_queries = 256
pending_query_timeout = "2s"
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::ValidationError);
    CHECK(result.error().message.find("ebpf.cleanup_interval") != std::string::npos);
}

TEST_CASE("eBPF packet poll timeout can override its default") {
    const auto path = write_config(
        "packet-poll-timeout.toml",
        R"(backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 2112
cleanup_interval = "10s"
packet_poll_timeout = "250ms"

[cache]
max_entries = 1024
max_response_bytes = 512
cache_negative = true
max_pending_queries = 256
pending_query_timeout = "2s"
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    REQUIRE(result.has_value());
    CHECK(std::get<shinku::config::EbpfConfig>(result->backend_config).packet_poll_timeout.count() == 250);
    CHECK(sink.messages().empty());
}

TEST_CASE("eBPF packet poll timeout rejects out of range values") {
    const auto path = write_config(
        "packet-poll-timeout-too-large.toml",
        R"(backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 2112
cleanup_interval = "10s"
packet_poll_timeout = "2s"

[cache]
max_entries = 1024
max_response_bytes = 512
cache_negative = true
max_pending_queries = 256
pending_query_timeout = "2s"
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::ValidationError);
    CHECK(result.error().message.find("ebpf.packet_poll_timeout") != std::string::npos);
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
max_pending_queries = 0
pending_query_timeout = "10ms"
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
max_pending_queries = 256
pending_query_timeout = "2s"
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::ValidationError);
    CHECK(result.error().message.contains("dpdk.server_port"));
}

TEST_CASE("cache response limit enforces the DNS profile range") {
    const auto path = write_config(
        "bad-response-limit.toml",
        R"(backend = "dpdk"

[dpdk]
client_port = 0
server_port = 1

[cache]
max_entries = 1
max_response_bytes = 513
cache_negative = true
max_pending_queries = 1
pending_query_timeout = "2s"
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::ValidationError);
    CHECK(result.error().message.contains("cache.max_response_bytes"));
}

TEST_CASE("pending query capacity must be positive") {
    const auto path = write_config(
        "bad-pending-capacity.toml",
        R"(backend = "dpdk"

[dpdk]
client_port = 0
server_port = 1

[cache]
max_entries = 1
max_response_bytes = 128
cache_negative = true
max_pending_queries = 0
pending_query_timeout = "2s"
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::ValidationError);
    CHECK(result.error().message.contains("cache.max_pending_queries"));
}

TEST_CASE("pending query timeout enforces its inclusive range") {
    const auto path = write_config(
        "bad-pending-timeout.toml",
        R"(backend = "dpdk"

[dpdk]
client_port = 0
server_port = 1

[cache]
max_entries = 1
max_response_bytes = 128
cache_negative = true
max_pending_queries = 1
pending_query_timeout = "11s"
)"
    );

    CapturingSink sink;
    auto result = shinku::config::load_config(path, sink);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == shinku::config::ConfigErrorCode::ValidationError);
    CHECK(result.error().message.contains("cache.pending_query_timeout"));
}

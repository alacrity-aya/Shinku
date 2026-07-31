// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config/toml_loader.h"
#include <format>

#define TOML_EXCEPTIONS 0
#include <toml++/toml.hpp>

#include <charconv>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <istream>
#include <limits>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <unordered_set>
#include <utility>

namespace shinku::config {
namespace {

constexpr std::string_view kBackendKey = "backend";

ConfigError make_error(ConfigErrorCode code, const std::filesystem::path& path, std::string message) {
    return ConfigError {
        .code = code,
        .path = path,
        .message = std::move(message),
    };
}

std::unexpected<ConfigError>
emit_error(DiagnosticSink& sink, ConfigErrorCode code, const std::filesystem::path& path, std::string message) {
    const ConfigError error = make_error(code, path, std::move(message));
    sink.error(error);
    return std::unexpected(error);
}

std::unexpected<ConfigError>
emit_validation_error(DiagnosticSink& sink, const std::filesystem::path& path, ConfigValidationError error) {
    switch (error) {
        case ConfigValidationError::EbpfArenaPagesTooSmall:
            return emit_error(
                sink,
                ConfigErrorCode::ValidationError,
                path,
                "invalid ebpf.arena_pages: minimum is 1024"
            );
        case ConfigValidationError::EbpfCleanupIntervalNotPositive:
            return emit_error(
                sink,
                ConfigErrorCode::ValidationError,
                path,
                "invalid duration ebpf.cleanup_interval: expected positive duration with unit ms, s, or m"
            );
        case ConfigValidationError::EbpfPacketPollTimeoutOutOfRange:
            return emit_error(
                sink,
                ConfigErrorCode::ValidationError,
                path,
                "invalid ebpf.packet_poll_timeout: expected duration from 1ms through 1s"
            );
        case ConfigValidationError::CacheMaxEntriesZero:
            return emit_error(
                sink,
                ConfigErrorCode::ValidationError,
                path,
                "invalid cache.max_entries: must be greater than zero"
            );
        case ConfigValidationError::CacheMaxResponseBytesOutOfRange:
            return emit_error(
                sink,
                ConfigErrorCode::ValidationError,
                path,
                "invalid cache.max_response_bytes: expected value from 128 through 512"
            );
        case ConfigValidationError::CacheMaxPendingQueriesZero:
            return emit_error(
                sink,
                ConfigErrorCode::ValidationError,
                path,
                "invalid cache.max_pending_queries: must be greater than zero"
            );
        case ConfigValidationError::CachePendingQueryTimeoutOutOfRange:
            return emit_error(
                sink,
                ConfigErrorCode::ValidationError,
                path,
                "invalid cache.pending_query_timeout: expected duration from 100ms through 10s"
            );
    }

    return emit_error(sink, ConfigErrorCode::ValidationError, path, "invalid configuration");
}

void emit_warning(DiagnosticSink& sink, const std::filesystem::path& path, std::string message) {
    sink.warning(
        ConfigWarning {
            .path = path,
            .message = std::move(message),
        }
    );
}

std::expected<toml::table, ConfigError>
parse_toml(std::istream& input, const std::filesystem::path& path, DiagnosticSink& sink) {
    toml::parse_result result = toml::parse(input, path.string());
    if (!result) {
        return emit_error(sink, ConfigErrorCode::ParseError, path, std::string(result.error().description()));
    }

    return std::move(result).table();
}

std::optional<std::string> string_value(const toml::table& table, std::string_view key) {
    const toml::node* node = table.get(key);
    if (node == nullptr)
        return std::nullopt;
    return node->value<std::string>();
}

template<std::unsigned_integral T>
std::optional<T> unsigned_integer_value(const toml::table& table, std::string_view key) {
    const toml::node* node = table.get(key);
    if (node == nullptr)
        return std::nullopt;

    const auto value = node->value<int64_t>();
    if (!value.has_value())
        return std::nullopt;

    const int64_t signed_value = value.value();
    if (signed_value < 0)
        return std::nullopt;

    const auto as_u64 = static_cast<uint64_t>(signed_value);
    if (as_u64 > std::numeric_limits<T>::max())
        return std::nullopt;
    return static_cast<T>(as_u64);
}

std::optional<bool> bool_value(const toml::table& table, std::string_view key) {
    const toml::node* node = table.get(key);
    if (node == nullptr)
        return std::nullopt;
    return node->value<bool>();
}

bool has_key(const toml::table& table, std::string_view key) {
    return table.get(key) != nullptr;
}

const toml::table* subtable(const toml::table& table, std::string_view key) {
    const toml::node* node = table.get(key);
    return (node != nullptr) ? node->as_table() : nullptr;
}

std::string join_key(std::string_view prefix, std::string_view key) {
    if (prefix.empty())
        return std::string(key);

    return std::format("{}.{}", prefix, key);
}

void warn_unknown_keys(
    const toml::table& table,
    std::string_view prefix,
    const std::unordered_set<std::string_view>& allowed,
    DiagnosticSink& sink,
    const std::filesystem::path& path
) {
    for (const auto& [key, _]: table) {
        const std::string_view key_view(key.str());
        if (!allowed.contains(key_view))
            emit_warning(sink, path, std::format("unknown key {}", join_key(prefix, key_view)));
    }
}

void warn_unknown_keys(const toml::table& root, DiagnosticSink& sink, const std::filesystem::path& path) {
    warn_unknown_keys(root, "", { "backend", "ebpf", "dpdk", "cache" }, sink, path);

    if (const toml::table* ebpf = subtable(root, "ebpf"); ebpf != nullptr)
        warn_unknown_keys(
            *ebpf,
            "ebpf",
            { "iface", "arena_pages", "cleanup_interval", "packet_poll_timeout" },
            sink,
            path
        );

    if (const toml::table* dpdk = subtable(root, "dpdk"); dpdk != nullptr)
        warn_unknown_keys(*dpdk, "dpdk", { "client_port", "server_port" }, sink, path);

    if (const toml::table* cache = subtable(root, "cache"); cache != nullptr)
        warn_unknown_keys(
            *cache,
            "cache",
            { "max_entries", "max_response_bytes", "cache_negative", "max_pending_queries", "pending_query_timeout" },
            sink,
            path
        );
}

template<typename T>
std::expected<T, ConfigError> require_unsigned(
    const toml::table& table,
    std::string_view key,
    std::string_view field_path,
    const std::filesystem::path& path,
    DiagnosticSink& sink
) {
    if (!has_key(table, key))
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required key " + std::string(field_path));

    auto value = unsigned_integer_value<T>(table, key);
    if (!value.has_value())
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "invalid type for key " + std::string(field_path));

    return value.value();
}

std::expected<std::string, ConfigError> require_string(
    const toml::table& table,
    std::string_view key,
    std::string_view field_path,
    const std::filesystem::path& path,
    DiagnosticSink& sink
) {
    if (!has_key(table, key))
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required key " + std::string(field_path));

    auto value = string_value(table, key);
    if (!value.has_value())
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "invalid type for key " + std::string(field_path));

    return value.value();
}

std::expected<bool, ConfigError> require_bool(
    const toml::table& table,
    std::string_view key,
    std::string_view field_path,
    const std::filesystem::path& path,
    DiagnosticSink& sink
) {
    if (!has_key(table, key))
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required key " + std::string(field_path));

    auto value = bool_value(table, key);
    if (!value.has_value())
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "invalid type for key " + std::string(field_path));

    return value.value();
}

std::optional<std::chrono::milliseconds> parse_duration(std::string_view text) {
    if (text.empty())
        return std::nullopt;

    std::string_view number_part;
    std::chrono::milliseconds multiplier;

    if (text.ends_with("ms")) {
        number_part = text.substr(0, text.size() - 2);
        multiplier = std::chrono::milliseconds(1);
    } else if (text.ends_with("s")) {
        number_part = text.substr(0, text.size() - 1);
        multiplier = std::chrono::seconds(1);
    } else if (text.ends_with("m")) {
        number_part = text.substr(0, text.size() - 1);
        multiplier = std::chrono::minutes(1);
    } else {
        return std::nullopt;
    }

    if (number_part.empty())
        return std::nullopt;

    uint64_t amount = 0;
    const auto* begin = number_part.data();
    const auto* end = number_part.data() + number_part.size();
    auto [ptr, ec] = std::from_chars(begin, end, amount);
    if (ec != std::errc() || ptr != end)
        return std::nullopt;

    const auto max_count = static_cast<uint64_t>(std::numeric_limits<std::chrono::milliseconds::rep>::max());
    const auto multiplier_count = static_cast<uint64_t>(multiplier.count());
    if (amount > max_count / multiplier_count)
        return std::nullopt;

    return std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(amount * multiplier.count()));
}

std::expected<BackendKind, ConfigError>
parse_backend_kind(const toml::table& root, const std::filesystem::path& path, DiagnosticSink& sink) {
    if (!has_key(root, kBackendKey))
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required key backend");

    auto backend = string_value(root, kBackendKey);
    if (!backend.has_value())
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "invalid type for key backend");

    const std::string& backend_value = backend.value();
    if (backend_value == "ebpf")
        return BackendKind::Ebpf;
    if (backend_value == "dpdk")
        return BackendKind::Dpdk;

    return emit_error(sink, ConfigErrorCode::UnsupportedBackend, path, "unsupported backend: " + backend_value);
}

std::expected<CacheConfig, ConfigError>
parse_cache_config(const toml::table& root, const std::filesystem::path& path, DiagnosticSink& sink) {
    const toml::table* cache = subtable(root, "cache");
    if (cache == nullptr)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required table cache");

    auto max_entries = require_unsigned<uint32_t>(*cache, "max_entries", "cache.max_entries", path, sink);
    if (!max_entries)
        return std::unexpected(max_entries.error());

    auto max_response_bytes =
        require_unsigned<uint32_t>(*cache, "max_response_bytes", "cache.max_response_bytes", path, sink);
    if (!max_response_bytes)
        return std::unexpected(max_response_bytes.error());

    auto cache_negative = require_bool(*cache, "cache_negative", "cache.cache_negative", path, sink);
    if (!cache_negative)
        return std::unexpected(cache_negative.error());

    auto max_pending_queries =
        require_unsigned<uint32_t>(*cache, "max_pending_queries", "cache.max_pending_queries", path, sink);
    if (!max_pending_queries)
        return std::unexpected(max_pending_queries.error());

    auto pending_query_timeout_text =
        require_string(*cache, "pending_query_timeout", "cache.pending_query_timeout", path, sink);
    if (!pending_query_timeout_text)
        return std::unexpected(pending_query_timeout_text.error());

    auto pending_query_timeout = parse_duration(*pending_query_timeout_text);
    if (!pending_query_timeout.has_value()) {
        return emit_error(
            sink,
            ConfigErrorCode::ValidationError,
            path,
            "invalid cache.pending_query_timeout: expected duration from 100ms through 10s"
        );
    }

    auto cache_config = CacheConfig::create({
        .max_entries = *max_entries,
        .max_response_bytes = *max_response_bytes,
        .cache_negative = *cache_negative,
        .max_pending_queries = *max_pending_queries,
        .pending_query_timeout = *pending_query_timeout,
    });
    if (!cache_config)
        return emit_validation_error(sink, path, cache_config.error());
    return std::move(*cache_config);
}

std::expected<EbpfConfig, ConfigError>
parse_ebpf_config(const toml::table& root, const std::filesystem::path& path, DiagnosticSink& sink) {
    const toml::table* ebpf = subtable(root, "ebpf");
    if (ebpf == nullptr)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required table ebpf");

    auto iface = require_string(*ebpf, "iface", "ebpf.iface", path, sink);
    if (!iface)
        return std::unexpected(iface.error());

    auto arena_pages = require_unsigned<uint32_t>(*ebpf, "arena_pages", "ebpf.arena_pages", path, sink);
    if (!arena_pages)
        return std::unexpected(arena_pages.error());

    auto cleanup_interval_text = require_string(*ebpf, "cleanup_interval", "ebpf.cleanup_interval", path, sink);
    if (!cleanup_interval_text)
        return std::unexpected(cleanup_interval_text.error());

    auto cleanup_interval = parse_duration(*cleanup_interval_text);
    if (!cleanup_interval.has_value()) {
        return emit_error(
            sink,
            ConfigErrorCode::ValidationError,
            path,
            "invalid duration ebpf.cleanup_interval: expected positive duration with unit ms, s, or m"
        );
    }

    auto packet_poll_timeout = EbpfConfig::kDefaultPacketPollTimeout;
    if (has_key(*ebpf, "packet_poll_timeout")) {
        auto timeout_text = string_value(*ebpf, "packet_poll_timeout");
        if (!timeout_text.has_value()) {
            return emit_error(
                sink,
                ConfigErrorCode::SchemaError,
                path,
                "invalid type for key ebpf.packet_poll_timeout"
            );
        }

        auto parsed_timeout = parse_duration(*timeout_text);
        if (!parsed_timeout.has_value()) {
            return emit_error(
                sink,
                ConfigErrorCode::ValidationError,
                path,
                "invalid ebpf.packet_poll_timeout: expected duration from 1ms through 1s"
            );
        }
        packet_poll_timeout = *parsed_timeout;
    }

    auto ebpf_config = EbpfConfig::create({
        .iface = *iface,
        .arena_pages = *arena_pages,
        .cleanup_interval = cleanup_interval.value(),
        .packet_poll_timeout = packet_poll_timeout,
    });
    if (!ebpf_config)
        return emit_validation_error(sink, path, ebpf_config.error());
    return std::move(*ebpf_config);
}

std::expected<DpdkConfig, ConfigError>
parse_dpdk_config(const toml::table& root, const std::filesystem::path& path, DiagnosticSink& sink) {
    const toml::table* dpdk = subtable(root, "dpdk");
    if (dpdk == nullptr)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required table dpdk");

    auto client_port = require_unsigned<uint16_t>(*dpdk, "client_port", "dpdk.client_port", path, sink);
    if (!client_port)
        return std::unexpected(client_port.error());

    auto server_port = require_unsigned<uint16_t>(*dpdk, "server_port", "dpdk.server_port", path, sink);
    if (!server_port)
        return std::unexpected(server_port.error());

    if (*client_port == *server_port) {
        return emit_error(
            sink,
            ConfigErrorCode::ValidationError,
            path,
            "invalid dpdk.server_port: server_port must differ from client_port"
        );
    }

    return DpdkConfig {
        .client_port = *client_port,
        .server_port = *server_port,
    };
}

} // namespace

void StderrDiagnosticSink::warning(const ConfigWarning& warning) {
    if (!warning.path.empty())
        std::print(stderr, "{}: ", warning.path.string());
    std::println(stderr, "warning: {}", warning.message);
}

void StderrDiagnosticSink::error(const ConfigError& error) {
    if (!error.path.empty())
        std::print(stderr, "{}: ", error.path.string());
    std::println(stderr, "error: {}", error.message);
}

std::expected<Config, ConfigError> load_config(const std::filesystem::path& path, DiagnosticSink& sink) {
    std::ifstream file(path);
    if (!file.is_open())
        return emit_error(sink, ConfigErrorCode::FileNotFound, path, "failed to open config file");

    auto root = parse_toml(file, path, sink);
    if (!root)
        return std::unexpected(root.error());

    warn_unknown_keys(*root, sink, path);

    auto backend = parse_backend_kind(*root, path, sink);
    if (!backend)
        return std::unexpected(backend.error());

    if (*backend == BackendKind::Ebpf) {
        auto ebpf = parse_ebpf_config(*root, path, sink);
        if (!ebpf)
            return std::unexpected(ebpf.error());
        auto cache = parse_cache_config(*root, path, sink);
        if (!cache)
            return std::unexpected(cache.error());
        return Config {
            .backend = *backend,
            .backend_config = *ebpf,
            .cache = *cache,
        };
    }

    auto dpdk = parse_dpdk_config(*root, path, sink);
    if (!dpdk)
        return std::unexpected(dpdk.error());
    auto cache = parse_cache_config(*root, path, sink);
    if (!cache)
        return std::unexpected(cache.error());
    return Config {
        .backend = *backend,
        .backend_config = *dpdk,
        .cache = *cache,
    };
}

} // namespace shinku::config

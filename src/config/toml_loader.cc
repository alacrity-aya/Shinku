// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config/toml_loader.h"

#include <toml++/toml.hpp>

#include <cerrno>
#include <charconv>
#include <cstdio>
#include <fstream>
#include <limits>
#include <optional>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <unordered_set>

namespace shinku::config {
namespace {

constexpr std::string_view kBackendKey = "backend";

ConfigError make_error(ConfigErrorCode code, const std::filesystem::path& path, std::string message) {
    return ConfigError{
        .code = code,
        .path = path,
        .message = std::move(message),
    };
}

std::unexpected<ConfigError>
emit_error(DiagnosticSink& sink, ConfigErrorCode code, const std::filesystem::path& path, std::string message) {
    ConfigError error = make_error(code, path, std::move(message));
    sink.error(error);
    return std::unexpected(error);
}

void emit_warning(DiagnosticSink& sink, const std::filesystem::path& path, std::string message) {
    sink.warning(ConfigWarning{
        .path = path,
        .message = std::move(message),
    });
}

std::optional<std::string> string_value(const toml::table& table, std::string_view key) {
    const toml::node* node = table.get(key);
    if (!node)
        return std::nullopt;
    if (const auto value = node->value<std::string>())
        return *value;
    return std::nullopt;
}

template <typename T>
std::optional<T> unsigned_integer_value(const toml::table& table, std::string_view key) {
    static_assert(std::is_unsigned_v<T>);

    const toml::node* node = table.get(key);
    if (!node)
        return std::nullopt;

    if (const auto value = node->value<std::int64_t>()) {
        if (*value < 0)
            return std::nullopt;
        const auto as_u64 = static_cast<std::uint64_t>(*value);
        if (as_u64 > std::numeric_limits<T>::max())
            return std::nullopt;
        return static_cast<T>(as_u64);
    }

    return std::nullopt;
}

std::optional<bool> bool_value(const toml::table& table, std::string_view key) {
    const toml::node* node = table.get(key);
    if (!node)
        return std::nullopt;
    if (const auto value = node->value<bool>())
        return *value;
    return std::nullopt;
}

bool has_key(const toml::table& table, std::string_view key) {
    return table.get(key) != nullptr;
}

const toml::table* subtable(const toml::table& table, std::string_view key) {
    const toml::node* node = table.get(key);
    return node ? node->as_table() : nullptr;
}

std::string join_key(std::string_view prefix, std::string_view key) {
    if (prefix.empty())
        return std::string(key);
    std::string out(prefix);
    out += ".";
    out += key;
    return out;
}

void warn_unknown_keys(
    const toml::table& table,
    std::string_view prefix,
    const std::unordered_set<std::string_view>& allowed,
    DiagnosticSink& sink,
    const std::filesystem::path& path
) {
    for (const auto& [key, node] : table) {
        (void)node;
        const std::string_view key_view(key.str());
        if (!allowed.contains(key_view))
            emit_warning(sink, path, "unknown key " + join_key(prefix, key_view));
    }
}

void warn_unknown_keys(const toml::table& root, DiagnosticSink& sink, const std::filesystem::path& path) {
    warn_unknown_keys(root, "", { "backend", "ebpf", "dpdk", "cache" }, sink, path);

    if (const toml::table* ebpf = subtable(root, "ebpf"))
        warn_unknown_keys(*ebpf, "ebpf", { "iface", "arena_pages", "cleanup_interval" }, sink, path);

    if (const toml::table* dpdk = subtable(root, "dpdk"))
        warn_unknown_keys(*dpdk, "dpdk", { "client_port", "server_port" }, sink, path);

    if (const toml::table* cache = subtable(root, "cache"))
        warn_unknown_keys(*cache, "cache", { "max_entries", "max_response_bytes", "cache_negative" }, sink, path);
}

template <typename T>
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
    if (!value)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "invalid type for key " + std::string(field_path));

    return *value;
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
    if (!value)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "invalid type for key " + std::string(field_path));

    return *value;
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
    if (!value)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "invalid type for key " + std::string(field_path));

    return *value;
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

    std::uint64_t amount = 0;
    const auto* begin = number_part.data();
    const auto* end = number_part.data() + number_part.size();
    auto [ptr, ec] = std::from_chars(begin, end, amount);
    if (ec != std::errc() || ptr != end || amount == 0)
        return std::nullopt;

    const auto max_count = std::numeric_limits<std::chrono::milliseconds::rep>::max();
    if (amount > static_cast<std::uint64_t>(max_count / multiplier.count()))
        return std::nullopt;

    return std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(amount * multiplier.count()));
}

std::expected<BackendKind, ConfigError>
parse_backend_kind(const toml::table& root, const std::filesystem::path& path, DiagnosticSink& sink) {
    if (!has_key(root, kBackendKey))
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required key backend");

    auto backend = string_value(root, kBackendKey);
    if (!backend)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "invalid type for key backend");

    if (*backend == "ebpf")
        return BackendKind::Ebpf;
    if (*backend == "dpdk")
        return BackendKind::Dpdk;

    return emit_error(sink, ConfigErrorCode::UnsupportedBackend, path, "unsupported backend: " + *backend);
}

std::expected<CacheConfig, ConfigError>
parse_cache_config(const toml::table& root, const std::filesystem::path& path, DiagnosticSink& sink) {
    const toml::table* cache = subtable(root, "cache");
    if (!cache)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required table cache");

    auto max_entries = require_unsigned<std::uint32_t>(*cache, "max_entries", "cache.max_entries", path, sink);
    if (!max_entries)
        return std::unexpected(max_entries.error());
    if (*max_entries == 0)
        return emit_error(sink, ConfigErrorCode::ValidationError, path, "invalid cache.max_entries: must be greater than zero");

    auto max_response_bytes =
        require_unsigned<std::uint32_t>(*cache, "max_response_bytes", "cache.max_response_bytes", path, sink);
    if (!max_response_bytes)
        return std::unexpected(max_response_bytes.error());
    if (*max_response_bytes == 0) {
        return emit_error(
            sink,
            ConfigErrorCode::ValidationError,
            path,
            "invalid cache.max_response_bytes: must be greater than zero"
        );
    }

    auto cache_negative = require_bool(*cache, "cache_negative", "cache.cache_negative", path, sink);
    if (!cache_negative)
        return std::unexpected(cache_negative.error());

    return CacheConfig{
        .max_entries = *max_entries,
        .max_response_bytes = *max_response_bytes,
        .cache_negative = *cache_negative,
    };
}

std::expected<EbpfConfig, ConfigError>
parse_ebpf_config(const toml::table& root, const std::filesystem::path& path, DiagnosticSink& sink) {
    const toml::table* ebpf = subtable(root, "ebpf");
    if (!ebpf)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required table ebpf");

    auto iface = require_string(*ebpf, "iface", "ebpf.iface", path, sink);
    if (!iface)
        return std::unexpected(iface.error());

    auto arena_pages = require_unsigned<std::uint32_t>(*ebpf, "arena_pages", "ebpf.arena_pages", path, sink);
    if (!arena_pages)
        return std::unexpected(arena_pages.error());
    if (*arena_pages < 1024)
        return emit_error(sink, ConfigErrorCode::ValidationError, path, "invalid ebpf.arena_pages: minimum is 1024");

    auto cleanup_interval_text = require_string(*ebpf, "cleanup_interval", "ebpf.cleanup_interval", path, sink);
    if (!cleanup_interval_text)
        return std::unexpected(cleanup_interval_text.error());

    auto cleanup_interval = parse_duration(*cleanup_interval_text);
    if (!cleanup_interval) {
        return emit_error(
            sink,
            ConfigErrorCode::ValidationError,
            path,
            "invalid duration ebpf.cleanup_interval: expected positive duration with unit ms, s, or m"
        );
    }

    return EbpfConfig{
        .iface = *iface,
        .arena_pages = *arena_pages,
        .cleanup_interval = *cleanup_interval,
    };
}

std::expected<DpdkConfig, ConfigError>
parse_dpdk_config(const toml::table& root, const std::filesystem::path& path, DiagnosticSink& sink) {
    const toml::table* dpdk = subtable(root, "dpdk");
    if (!dpdk)
        return emit_error(sink, ConfigErrorCode::SchemaError, path, "missing required table dpdk");

    auto client_port = require_unsigned<std::uint16_t>(*dpdk, "client_port", "dpdk.client_port", path, sink);
    if (!client_port)
        return std::unexpected(client_port.error());

    auto server_port = require_unsigned<std::uint16_t>(*dpdk, "server_port", "dpdk.server_port", path, sink);
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

    return DpdkConfig{
        .client_port = *client_port,
        .server_port = *server_port,
    };
}

} // namespace

void StderrDiagnosticSink::warning(const ConfigWarning& warning) {
    if (!warning.path.empty())
        std::fprintf(stderr, "%s: ", warning.path.string().c_str());
    std::fprintf(stderr, "warning: %s\n", warning.message.c_str());
}

void StderrDiagnosticSink::error(const ConfigError& error) {
    if (!error.path.empty())
        std::fprintf(stderr, "%s: ", error.path.string().c_str());
    std::fprintf(stderr, "error: %s\n", error.message.c_str());
}

std::expected<Config, ConfigError> load_config(const std::filesystem::path& path, DiagnosticSink& sink) {
    std::ifstream file(path);
    if (!file.is_open())
        return emit_error(sink, ConfigErrorCode::FileNotFound, path, "failed to open config file");

    toml::table root;
    try {
        root = toml::parse(file, path.string());
    } catch (const toml::parse_error& err) {
        return emit_error(sink, ConfigErrorCode::ParseError, path, std::string(err.description()));
    } catch (const std::ios_base::failure& err) {
        return emit_error(sink, ConfigErrorCode::ReadError, path, err.what());
    }

    if (file.bad())
        return emit_error(sink, ConfigErrorCode::ReadError, path, "failed to read config file");

    warn_unknown_keys(root, sink, path);

    auto backend = parse_backend_kind(root, path, sink);
    if (!backend)
        return std::unexpected(backend.error());

    if (*backend == BackendKind::Ebpf) {
        auto ebpf = parse_ebpf_config(root, path, sink);
        if (!ebpf)
            return std::unexpected(ebpf.error());
        auto cache = parse_cache_config(root, path, sink);
        if (!cache)
            return std::unexpected(cache.error());
        return Config{
            .backend = *backend,
            .backend_config = *ebpf,
            .cache = *cache,
        };
    }

    auto dpdk = parse_dpdk_config(root, path, sink);
    if (!dpdk)
        return std::unexpected(dpdk.error());
    auto cache = parse_cache_config(root, path, sink);
    if (!cache)
        return std::unexpected(cache.error());
    return Config{
        .backend = *backend,
        .backend_config = *dpdk,
        .cache = *cache,
    };
}

} // namespace shinku::config

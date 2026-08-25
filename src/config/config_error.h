// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace shinku::config {

/// Failure codes returned when loading or validating a configuration file.
enum class ConfigErrorCode : uint8_t {
    FileNotFound, ///< The configuration file did not exist.
    ReadError, ///< The file existed but could not be read.
    ParseError, ///< The file could not be parsed as TOML.
    SchemaError, ///< The TOML was valid but did not match the expected schema.
    ValidationError, ///< A parsed value failed a semantic validation rule.
    UnsupportedBackend, ///< The selected backend is not supported on this host.
};

/// Error returned by configuration loading, carrying the offending path and a message.
struct ConfigError {
    ConfigErrorCode code; ///< The failure category.
    std::filesystem::path path; ///< Path of the configuration file involved.
    std::string message; ///< Human-readable description of the failure.
};

/// A non-fatal configuration issue surfaced during loading.
struct ConfigWarning {
    std::filesystem::path path; ///< Path of the configuration file involved.
    std::string message; ///< Human-readable description of the warning.
};

} // namespace shinku::config

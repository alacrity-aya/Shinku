// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <filesystem>
#include <string>

namespace shinku::config {

enum class ConfigErrorCode {
    FileNotFound,
    ReadError,
    ParseError,
    SchemaError,
    ValidationError,
    UnsupportedBackend,
};

struct ConfigError {
    ConfigErrorCode code;
    std::filesystem::path path;
    std::string message;
};

struct ConfigWarning {
    std::filesystem::path path;
    std::string message;
};

} // namespace shinku::config

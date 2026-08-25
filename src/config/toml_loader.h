// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "config.h"
#include "config_error.h"
#include "diagnostic_sink.h"

#include <expected>
#include <filesystem>

namespace shinku::config {

/**
 * @brief Load and validate a configuration file into a @ref Config.
 *
 * Reads the TOML file at @p path, parses it against the expected schema,
 * validates each value semantically, and emits any non-fatal issues via
 * @p sink. A returned error means the configuration could not be used.
 *
 * @param path Path to the TOML configuration file.
 * @param sink Sink that receives warnings and errors during loading.
 * @return The resolved configuration, or a @ref ConfigError on failure.
 */
std::expected<Config, ConfigError> load_config(const std::filesystem::path& path, DiagnosticSink& sink);

} // namespace shinku::config

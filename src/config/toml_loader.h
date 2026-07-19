// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "config.h"
#include "config_error.h"
#include "diagnostic_sink.h"

#include <expected>
#include <filesystem>

namespace shinku::config {

std::expected<Config, ConfigError> load_config(const std::filesystem::path& path, DiagnosticSink& sink);

} // namespace shinku::config

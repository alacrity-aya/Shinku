// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "config.h"
#include "config_error.h"
#include "runtime/legacy_env.h"

#include <expected>

namespace shinku::config {

std::expected<env, ConfigError> to_legacy_env(const Config& config);

} // namespace shinku::config

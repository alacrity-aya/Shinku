// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend.h"
#include "backend_error.h"
#include "config/config.h"

#include <expected>
#include <memory>

namespace shinku::backend {

[[nodiscard]] std::expected<std::unique_ptr<Backend>, BackendError> make_backend(const config::Config& config);

} // namespace shinku::backend

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend.h"
#include "backend_error.h"
#include "config/config.h"

#include <expected>
#include <memory>
#include <span>
#include <string>

namespace shinku::backend {

/**
 * @brief Construct a concrete @ref Backend from a resolved configuration.
 *
 * Selects an eBPF or DPDK backend based on @ref config::Config::backend and
 * constructs it with the supplied DPDK EAL arguments when applicable.
 *
 * @param config The resolved application configuration.
 * @param dpdk_arguments EAL arguments to forward to a DPDK backend; ignored by eBPF.
 * @return A ready-to-run backend, or a @ref BackendError describing why construction failed.
 */
[[nodiscard]] std::expected<std::unique_ptr<Backend>, BackendError>
make_backend(const config::Config& config, std::span<const std::string> dpdk_arguments = {});

} // namespace shinku::backend

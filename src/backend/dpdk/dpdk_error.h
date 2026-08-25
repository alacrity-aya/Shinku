// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <optional>
#include <string>
#include <system_error>

namespace shinku::backend::dpdk {

/// Error returned by DPDK backend operations, carrying an optional cause.
struct DpdkError {
    std::string operation; ///< Name of the DPDK operation that failed.
    std::string detail; ///< Human-readable description of the failure.
    std::optional<std::error_code> cause; ///< Underlying system error, if any.
};

} // namespace shinku::backend::dpdk

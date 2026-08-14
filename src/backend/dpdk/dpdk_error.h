// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <optional>
#include <string>
#include <system_error>

namespace shinku::backend::dpdk {

struct DpdkError {
    std::string operation;
    std::string detail;
    std::optional<std::error_code> cause;
};

} // namespace shinku::backend::dpdk

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/stop_condition.h"

#include <string_view>
#include <utility>

namespace shinku::backend {

std::string_view stop_reason_name(StopReason reason) noexcept {
    switch (reason) {
        case StopReason::Signal:
            return "signal";
        case StopReason::Manual:
            return "manual";
        case StopReason::Timeout:
            return "timeout";
    }
    std::unreachable();
}

} // namespace shinku::backend

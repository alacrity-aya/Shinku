// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace shinku::backend {

enum class StopReason : uint8_t {
    Signal,
    Manual,
    Timeout,
};

struct StopRequest {
    StopReason reason;
};

[[nodiscard]] std::string_view stop_reason_name(StopReason reason) noexcept;

class StopCondition {
public:
    StopCondition(const StopCondition&) = delete;
    StopCondition& operator=(const StopCondition&) = delete;
    StopCondition(StopCondition&&) = delete;
    StopCondition& operator=(StopCondition&&) = delete;
    virtual ~StopCondition() = default;

    [[nodiscard]] virtual std::optional<StopRequest> poll() noexcept = 0;

protected:
    StopCondition() = default;
};

} // namespace shinku::backend

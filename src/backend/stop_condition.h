// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace shinku::backend {

/// Why a run loop was asked to stop.
enum class StopReason : uint8_t {
    Signal, ///< A signal (e.g. SIGINT/SIGTERM) requested shutdown.
    Manual, ///< An explicit programmatic stop was requested.
    Timeout, ///< A configured runtime deadline elapsed.
};

/// A request to stop the run loop, carrying the originating reason.
struct StopRequest {
    StopReason reason; ///< The reason shutdown was requested.
};

/**
 * @brief Return a human-readable name for a @ref StopReason.
 * @param reason The reason to name.
 * @return A stable string view naming the reason.
 */
[[nodiscard]] std::string_view stop_reason_name(StopReason reason) noexcept;

/**
 * @brief Abstract interface polled by the run loop to detect shutdown.
 *
 * Concrete stop conditions (signal-driven, timeout-driven) implement this so
 * the @ref BackendRunner can check for a stop request each iteration without
 * coupling to the underlying mechanism.
 */
class StopCondition {
public:
    StopCondition(const StopCondition&) = delete;
    StopCondition& operator=(const StopCondition&) = delete;
    StopCondition(StopCondition&&) = delete;
    StopCondition& operator=(StopCondition&&) = delete;
    virtual ~StopCondition() = default;

    /**
     * @brief Poll for a pending stop request.
     * @return A @ref StopRequest if shutdown has been requested, otherwise empty.
     */
    [[nodiscard]] virtual std::optional<StopRequest> poll() noexcept = 0;

protected:
    StopCondition() = default;
};

} // namespace shinku::backend

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "process_control.h"

namespace shinku::process_control {

/**
 * @brief Test-only accessor for resetting @ref ProcessControl shutdown state.
 *
 * Production code must never call this. It exists so unit tests can restore a
 * clean shutdown state between cases without exposing a reset method on the
 * public ProcessControl interface.
 */
class ProcessControlTestAccess final {
public:
    /// @brief Reset the ProcessControl shutdown request; tests only.
    static void reset_shutdown_request() noexcept {
        ProcessControl::reset_for_tests();
    }

private:
    ProcessControlTestAccess() = default;
};

} // namespace shinku::process_control

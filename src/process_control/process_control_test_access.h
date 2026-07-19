// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "process_control.h"

namespace shinku::process_control {

class ProcessControlTestAccess final {
public:
    static void reset_shutdown_request(ProcessControl& control = ProcessControl::instance()) noexcept {
        control.reset_for_tests();
    }

private:
    ProcessControlTestAccess() = default;
};

} // namespace shinku::process_control

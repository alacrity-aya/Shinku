// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "process_control/process_control.h"
#include "process_control/process_control_test_access.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("ProcessControl starts without a shutdown request") {
    auto& process_control = shinku::process_control::ProcessControl::instance();
    shinku::process_control::ProcessControlTestAccess::reset_shutdown_request(process_control);

    CHECK_FALSE(process_control.shutdown_requested());
}

TEST_CASE("ProcessControl shutdown request is sticky") {
    auto& process_control = shinku::process_control::ProcessControl::instance();
    shinku::process_control::ProcessControlTestAccess::reset_shutdown_request(process_control);

    process_control.request_shutdown();
    CHECK(process_control.shutdown_requested());

    process_control.request_shutdown();
    CHECK(process_control.shutdown_requested());
}

TEST_CASE("ProcessControl test access resets shutdown request") {
    auto& process_control = shinku::process_control::ProcessControl::instance();

    process_control.request_shutdown();
    REQUIRE(process_control.shutdown_requested());

    shinku::process_control::ProcessControlTestAccess::reset_shutdown_request(process_control);
    CHECK_FALSE(process_control.shutdown_requested());
}

TEST_CASE("ProcessControl signal handler installation is idempotent") {
    auto& process_control = shinku::process_control::ProcessControl::instance();

    auto first_install = process_control.install_signal_handlers();
    REQUIRE(first_install.has_value());

    auto second_install = process_control.install_signal_handlers();
    CHECK(second_install.has_value());
}

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "process_control/process_control.h"
#include "process_control/process_control_test_access.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("ProcessControl starts without a shutdown request") {
    auto& process_control = shinku::process_control::ProcessControl::instance();
    shinku::process_control::ProcessControlTestAccess::reset_shutdown_request();

    CHECK_FALSE(shinku::process_control::ProcessControl::shutdown_requested());
    CHECK_FALSE(process_control.poll().has_value());
}

TEST_CASE("ProcessControl shutdown request is sticky") {
    auto& process_control = shinku::process_control::ProcessControl::instance();
    shinku::process_control::ProcessControlTestAccess::reset_shutdown_request();

    shinku::process_control::ProcessControl::request_shutdown();
    CHECK(shinku::process_control::ProcessControl::shutdown_requested());

    auto first_request = process_control.poll();
    REQUIRE(first_request.has_value());
    CHECK(first_request->reason == shinku::backend::StopReason::Signal);

    auto second_request = process_control.poll();
    REQUIRE(second_request.has_value());
    CHECK(second_request->reason == shinku::backend::StopReason::Signal);
}

TEST_CASE("ProcessControl test access resets shutdown request") {
    auto& process_control = shinku::process_control::ProcessControl::instance();

    shinku::process_control::ProcessControl::request_shutdown();
    REQUIRE(shinku::process_control::ProcessControl::shutdown_requested());

    shinku::process_control::ProcessControlTestAccess::reset_shutdown_request();
    CHECK_FALSE(shinku::process_control::ProcessControl::shutdown_requested());
    CHECK_FALSE(process_control.poll().has_value());
}

TEST_CASE("ProcessControl signal handler installation is idempotent") {
    auto first_install = shinku::process_control::ProcessControl::install_signal_handlers();
    REQUIRE(first_install.has_value());

    auto second_install = shinku::process_control::ProcessControl::install_signal_handlers();
    CHECK(second_install.has_value());
}

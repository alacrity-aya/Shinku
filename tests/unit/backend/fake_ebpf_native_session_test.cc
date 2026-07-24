// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "fake_ebpf_native_session.h"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <system_error>

using shinku::backend::ebpf::testing::FakeEbpfNativeSession;

TEST_CASE("FakeEbpfNativeSession scripts independent native actions") {
    FakeEbpfNativeSession session;
    const auto busy = std::make_error_code(std::errc::device_or_resource_busy);
    session.xdp_results = { std::unexpected(busy), {} };

    auto first = session.attach_xdp(7);
    auto second = session.attach_xdp(7);

    REQUIRE_FALSE(first.has_value());
    CHECK(first.error() == busy);
    CHECK(second.has_value());
    CHECK(session.attached_ifindex == 7);
}

TEST_CASE("FakeEbpfNativeSession scripts release retries") {
    FakeEbpfNativeSession session;
    const auto failure = std::make_error_code(std::errc::io_error);
    session.release_results = { std::unexpected(failure), {} };

    auto first = session.release();
    auto second = session.release();

    REQUIRE_FALSE(first.has_value());
    CHECK(first.error() == failure);
    CHECK(second.has_value());
}

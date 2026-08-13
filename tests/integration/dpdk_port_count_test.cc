// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_native_session.h"

#include <cstddef>
#include <print>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    std::vector<std::string> eal_arguments;
    eal_arguments.reserve(static_cast<size_t>(argc - 1));
    for (int index = 1; index < argc; ++index)
        eal_arguments.emplace_back(argv[index]);

    shinku::backend::dpdk::ProductionDpdkNativeSession session;
    auto start_result = session.start(eal_arguments);
    if (start_result) {
        std::println(stderr, "DPDK Port count gate unexpectedly accepted a one-port topology");
        return 1;
    }
    if (start_result.error().operation != "port discovery") {
        std::println(stderr, "DPDK Port count gate failed at {}", start_result.error().operation);
        return 1;
    }

    auto release_result = session.release();
    if (!release_result) {
        std::println(stderr, "DPDK Port count cleanup failed at {}", release_result.error().operation);
        return 1;
    }

    std::println("DPDK Port count gate passed: one available port was rejected and released");
    return 0;
}

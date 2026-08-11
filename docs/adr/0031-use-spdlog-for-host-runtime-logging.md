# Use spdlog for Host Runtime Logging

Status: accepted

Shinku uses `spdlog` 1.17.0 as the Host Runtime logging implementation. Meson obtains it through the pinned WrapDB
wrap when a suitable system dependency is unavailable. Module 9 may introduce the dependency and emit a deliberately
small set of synchronous DPDK lifecycle and state-transition logs. Module 9 calls the `spdlog::info()`,
`spdlog::warn()`, and `spdlog::error()` convenience functions directly and uses spdlog's process-global default logger;
it does not add logger parameters, a Shinku logging facade, or a diagnostics-injection boundary. Module 10 still owns
the unified Runtime Diagnostics boundary, routing, formatting, and migration of existing eBPF/C-boundary output, and may
revisit the global access model when that broader boundary is implemented.

DPDK EAL and PMD diagnostics remain native `rte_log` output rather than being intercepted or translated by Module 9.
Runtime logging does not replace typed `std::expected`/`BackendError` control flow, and the DPDK packet path must not log
per packet, per burst, or for every empty Poll Quantum. Selecting `spdlog` does not by itself authorize an asynchronous
logger, file output, rotation, metrics, or restoration of the deleted Observability Surface. The global default logger
is an explicit Module 9 simplicity tradeoff rather than a new Backend interface requirement.

This accepts one maintained dependency instead of growing an interim `fprintf()` logging facade that Module 10 would
immediately replace. Pinning the WrapDB source and patch hashes keeps fallback builds reproducible while still allowing
Meson to use a compatible system dependency according to the project's dependency policy.

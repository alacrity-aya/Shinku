# DPDK Uses BOOTTIME

Status: accepted

Module 9B derives DPDK Cache Time, Pending Time, Response Observation Time, and maintenance deadlines from nanoseconds
returned by `clock_gettime(CLOCK_BOOTTIME)`. System suspend therefore consumes DNS TTL, Pending inactivity timeout, and
cleanup intervals, matching the eBPF `bpf_ktime_get_boot_ns()` semantic domain.

The Backend exposes no clock mode and does not substitute `CLOCK_MONOTONIC`, wall time, `rte_get_timer_cycles()`, or raw
TSC conversion. [ADR-0069](0069-dpdk-time-read-failure-is-fail-open.md) defines source-failure behavior without silently
changing clock domain. Tests inject explicit typed time values rather than sleeping.

A future hot-path optimization may change time-read sampling or use a proven equivalent source only after measurement,
but it must preserve BOOTTIME suspend semantics and all Cache/Pending boundary behavior.

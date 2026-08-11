# DPDK Time Read Failure Is Fail-open

Status: accepted

A `CLOCK_BOOTTIME` read failure is local Fail-open degradation and never changes `Backend::poll()` from success to
`PollFailed`. The affected Client packet performs no Cache lookup or Pending mutation and forwards unchanged to the
service. The affected Service packet performs no Pending claim, `DnsPolicy` classification, or Cache Fill and forwards
unchanged to the client. These paths preserve transparent forwarding without making expiration or observation decisions
from unknown time.

A Cache or Pending maintenance task that cannot obtain its one batch timestamp performs no inspection or deletion. It
leaves its current deadline, cursor, remaining count, and Entry ownership unchanged, then retries time acquisition in
the next Poll Quantum. This is distinct from a deletion failure, which ends the sweep and retries at the next normal
deadline.

No path reuses an earlier timestamp or selects another clock. Client packet, Service packet, and maintenance source
failures each emit at most one `spdlog::warn()` per Backend lifetime, preventing a persistent clock failure from logging
on every packet or quantum. Module 10 may replace this minimal per-category suppression with unified Runtime
Diagnostics without changing the Fail-open behavior.

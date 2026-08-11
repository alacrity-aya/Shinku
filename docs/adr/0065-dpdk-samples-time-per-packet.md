# DPDK Samples Time Per Packet

Status: accepted

Every Module 9B packet that reaches a Cache or Pending time-dependent decision reads `CLOCK_BOOTTIME` at that packet's
processing point. Cache Hit expiry and TTL aging, eligible Query Pending refresh, and correlated Response timeout and
observation do not reuse a timestamp captured at burst or Poll Quantum start.

Each 32-Entry Cache Cleanup or Pending Cleanup batch reads one fresh BOOTTIME value and applies it to that bounded batch.
The design therefore tolerates scheduler preemption or suspend between packets without paying one clock read per
maintenance Entry.

Benchmark backlog `PERF-9B-6` may compare one read per packet burst only if it preserves every expiration boundary under
injected long pauses and provides a predeclared material benefit. One timestamp for an entire Poll Quantum is not a
candidate because it spans both packet directions and both maintenance tasks.

# Backend Poll Is a Bounded Progress Quantum

Status: accepted

One `Backend::poll()` call performs a bounded, Backend-defined Poll Quantum and then returns control to
`BackendRunner`. A quantum may include a bounded backend-native readiness wait, as the eBPF Backend does, but it may not
contain an unbounded wait or drain an unbounded backlog. The Backend's work and wait bounds are part of its interface
because Runner observes the Stop Condition only between quanta.

The DPDK Backend uses a nonblocking quantum with bounded RX/TX bursts in both directions. `BackendRunner` immediately
begins the next Stop Condition/poll iteration after any successful quantum. ADR-0047 removes the former binary activity
result because Runner applied identical pacing to both values. This preserves a DPDK PMD busy-poll loop while allowing
eBPF to use its bounded event readiness wait behind the same small lifecycle interface.

This clarifies and supersedes the earlier wording that `poll()` must merely "return quickly" and must not hide any
blocking wait. The required property is a documented upper bound, not identical waiting behavior across Backends.

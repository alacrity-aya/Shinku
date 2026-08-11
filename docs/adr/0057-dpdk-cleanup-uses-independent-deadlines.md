# DPDK Cleanup Uses Independent Deadlines

Status: accepted

Module 9B Cache Cleanup and Pending Cleanup maintain independent deadlines. Cache first becomes due at the configured
`cleanup_interval`; Pending first becomes due at `pending_query_timeout / 2`. Each task retains its own cursor,
remaining-count, and continuation state.

When a task becomes due, `more_work` keeps it due on the following Poll Quantum, so one 32-Entry batch runs per quantum
until the task completes one capacity-wide sweep. The next deadline is scheduled from sweep completion. A cleanup error
ends that sweep and schedules a retry at the next normal deadline; it does not fail the Backend or alter the other task's
cadence. Cache and Pending deadlines never share a timer or rotate the fixed Client, Service, Cache, Pending task order.

This preserves the eBPF cleanup timing semantics while adapting execution to DPDK's single-lcore cooperative scheduler.
The bounded continuation prevents a complete table scan from occupying one Poll Quantum, and the independent deadlines
prevent one maintenance population from starving the other.

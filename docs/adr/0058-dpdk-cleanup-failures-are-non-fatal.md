# DPDK Cleanup Failures Are Non-fatal

Status: accepted

An operational deletion failure in DPDK Cache Cleanup or Pending Cleanup is task-local and non-fatal. The task retains
the failed Entry's ownership and does not return it to its free list. It continues no further deletion in the failed
sweep, but the cooperative scheduler continues both packet paths and the other maintenance task; `Backend::poll()`
returns success.

The failure is sent to the diagnostics/logging path with suppression rather than logged on every quantum. The affected
task retries at its next normal independent deadline. Until deletion succeeds, Hit-time expiry and Pending timeout
checks remain authoritative, so correctness is preserved while physical capacity may be temporarily reduced. The
failure never becomes `PollFailed` or changes Backend Lifecycle state.

This retains the shared Cache Store Fail-open contract and eBPF CleanupWorker behavior without adding a DPDK cleanup
thread.

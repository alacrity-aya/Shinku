# Backend Poll Reports Only Success or Failure

Status: accepted

The shared Backend interface removes `PollStatus` and defines:

```cpp
[[nodiscard]] virtual std::expected<void, BackendError> poll() = 0;
```

Success means one bounded Backend Poll Quantum completed. It does not distinguish packet activity, maintenance work,
readiness timeout, or an interruption that leaves no work. Failure means the Backend cannot continue and returns a typed
`BackendError`; `BackendErrorCode::PollFailed` remains the runtime-progress error classification.

`BackendRunner` previously ignored `PollStatus::WorkDone` and `PollStatus::NoWork` and immediately performed the same
next Stop Condition/poll iteration for both. The binary result therefore added interface surface without affecting
pacing, lifecycle, shutdown responsiveness, or error handling. A universal idle policy remains invalid because DPDK
uses nonblocking busy polling while eBPF performs its bounded readiness wait inside its own quantum.

Backends retain private information needed to implement their quantum. eBPF may retain native event counts and treats
timeout or `EINTR` as successful completion; DPDK tasks may retain deadline, cursor, continuation, ownership, or focused
test results. Runtime Diagnostics must expose meaningful backend-specific counters through its own interface rather than
reintroducing an activity bit at the lifecycle seam.

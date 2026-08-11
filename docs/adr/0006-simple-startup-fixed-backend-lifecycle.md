# Simple Startup-fixed Backend Lifecycle

Shinku Backend lifecycle will use a small public state machine: `Created -> Running -> Stopped -> Failed`. Backend selection is fixed at process startup, and runtime backend switching is out of scope. `probe()` is a pre-start capability check with no persistent side effects; it may inspect validated configuration and system capabilities, but it must not reserve resources, start packet processing, attach programs, spawn threads, or mutate global state. A successful probe means the selected Backend is supported; unsupported capability, permission, and probe execution failures are returned as typed `BackendError` values with human-readable messages. The first runtime driver is a simple loop that calls `poll()` until a separate process-control module requests shutdown. ADR-0023 later clarifies the original "return quickly" wording as a bounded Backend Poll Quantum that may include a bounded backend-native readiness wait, and ADR-0047 removes the unused idle/activity result so `poll()` reports only success or typed failure.

**Considered Options**

- Expose a detailed lifecycle with `Probed`, `Configured`, `Stopping`, and other intermediate states.
- Let `probe()` allocate or reserve expensive backend resources.
- Allow runtime switching between eBPF and DPDK backends.
- Keep lifecycle simple, make `probe()` a no-persistent-side-effect gate, and select the backend only at startup.
- Treat an unsupported selected backend as startup failure instead of falling back to a different backend or storage mode.
- Return unsupported capability as a separate probe success value.
- Return every probe failure, including unsupported capability, as `BackendError`.
- Let each backend own hidden worker threads after `start()`.
- Drive backend progress explicitly through a synchronous `poll()` loop.
- Allow `poll()` to block internally for a bounded wait.
- Initially require `poll()` to return quickly and report `NoWork` when idle; ADR-0047 later removes that unused result.

**Consequences**

The first C++ abstraction stays small and easier to adapt around the current eBPF backend. Startup errors must be reported through typed status, and any real resource acquisition must happen after backend selection, not during probing. If the selected eBPF backend cannot run because BPF arena support is unavailable, startup reports unsupported eBPF and fails rather than switching to a compatible store. Probe errors remain machine-readable while still giving an operator a direct reason for the failure. Runtime progress is explicit: the Host Runtime owns the loop, while the process-control module only translates OS signals into shutdown requests. ADR-0023 makes shutdown responsiveness depend on each Backend's documented Poll Quantum bound, and ADR-0047 keeps idle and activity facts private because Runner has no distinct policy for them.

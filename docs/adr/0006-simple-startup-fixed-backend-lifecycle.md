# Simple Startup-fixed Backend Lifecycle

Shinku Backend lifecycle will use a small public state machine: `Created -> Running -> Stopped -> Failed`. Backend selection is fixed at process startup, and runtime backend switching is out of scope. `probe()` is a pure pre-start capability check with no side effects; it may inspect validated configuration and system capabilities, but it must not reserve resources, start packet processing, attach programs, spawn threads, or mutate global state. Probe results carry both typed capability status and human-readable explanation messages. The first runtime driver is a simple loop that calls `poll_once()` until a separate process-control module requests shutdown; `poll_once()` must return quickly and returns `NoWork` when there is no backend work to process.

**Considered Options**

- Expose a detailed lifecycle with `Probed`, `Configured`, `Stopping`, and other intermediate states.
- Let `probe()` allocate or reserve expensive backend resources.
- Allow runtime switching between eBPF and DPDK backends.
- Keep lifecycle simple, make `probe()` pure, and select the backend only at startup.
- Treat an unsupported selected backend as startup failure instead of falling back to a different backend or storage mode.
- Return only a typed probe status without explanatory messages.
- Return typed probe status with explanatory messages.
- Let each backend own hidden worker threads after `start()`.
- Drive backend progress explicitly through a synchronous `poll_once()` loop.
- Allow `poll_once()` to block internally for a bounded wait.
- Require `poll_once()` to return quickly and report `NoWork` when idle.

**Consequences**

The first C++ abstraction stays small and easier to adapt around the current eBPF backend. Startup errors must be reported through typed status, and any real resource acquisition must happen after backend selection, not during probing. If the selected eBPF backend cannot run because BPF arena support is unavailable, startup reports unsupported eBPF and fails rather than switching to a compatible store. Probe failures remain machine-readable while still giving an operator a direct reason for the failure. Runtime progress is explicit: the Host Runtime owns the loop, while the process-control module only translates OS signals into shutdown requests. Idle handling is explicit through `NoWork`, so shutdown responsiveness does not depend on hidden backend blocking.

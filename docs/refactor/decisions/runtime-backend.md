# Runtime and Backend Decisions

## Segment 10: Backend Interface Shape

Decisions:

1. The first C++ `Backend` interface is synchronous: `start()`, `poll()`, and `stop()`.
2. Backend construction receives one `BackendConfig` variant that contains either `EbpfConfig` or `DpdkConfig`.
3. Backends do not own hidden background threads in the first interface. The Host Runtime drives progress by calling `poll()`.
4. `probe()` returns success only when the selected Backend is supported; unsupported capability, permission, wrong-config, and probe execution failures return `BackendError` with human-readable messages.
5. Backend abstraction files live in `src/backend/`.
6. The public `Backend` interface is a pure virtual class. CRTP is not used as the public interface because backend selection is runtime-configured; CRTP may be used later only as a private implementation helper.
7. `BackendRunner` owns lifecycle sequencing for `Created -> Running -> Stopped -> Failed`; backend implementations only perform backend-specific resource actions.
8. Superseded by decision 58. The initial interface returned `std::expected<PollStatus, BackendError>` with
   `WorkDone` and `NoWork`; Runner never consumed the distinction.
9. `stop()` is idempotent and returns success if the backend is already stopped.
10. Module 6 uses a minimal file layout: `backend.h`, `backend_error.h`, `backend_runner.h`, and `backend_runner.cc`.
11. `BackendError` uses a typed enum, message, and optional `std::error_code` cause.
12. `probe()` returns `std::expected<void, BackendError>`.
13. `BackendRunner::start()` calls `probe()` automatically before backend resource acquisition.
14. A `PollFailed` result moves `BackendRunner` to `Failed` in the MVP.
15. Module 6 does not implement a production `BackendFactory`; introduce the `make_backend()` free function in Module 7 with the real eBPF Backend.
16. `BackendRunner` exposes `BackendState state() const noexcept` for read-only lifecycle inspection.
17. `Backend` destructor does not call `stop()`; explicit shutdown belongs to `BackendRunner`.
18. Backend implementations report lifecycle failures through `std::expected`, not exceptions. `BackendRunner` destructor performs best-effort `stop()` and discards the returned status because destructors cannot report typed errors.
19. `BackendRunner::probe()` returns `InvalidState` while the runner is `Running`.
20. If `BackendRunner::start()` gets a probe error, the runner enters `Failed` and propagates that `BackendError`.
21. Module 6 initially made explicit `BackendRunner::stop()` from `Failed` transition to `Stopped` after successful cleanup. Module 7 supersedes that state outcome for the runner-owned `run()` path: cleanup is still attempted, but the runtime failure outcome remains `Failed`.
22. `BackendErrorCode::Unsupported` covers selected backend or host capability cases where startup cannot proceed, including unavailable BPF arena support.
23. `BackendErrorCode::PermissionDenied` covers missing privileges discovered before backend start.
24. `BackendErrorCode` starts with `InvalidState`, `WrongConfig`, `Unsupported`, `PermissionDenied`, `ProbeFailed`, `StartFailed`, `PollFailed`, and `StopFailed`.
25. `BackendRunner` owns its backend through `std::unique_ptr<Backend>`.
26. Fake backend tests live in `tests/unit/backend/backend_runner_test.cc`.
27. Backend runner tests cover happy path and lifecycle edges: initial state, automatic probe on start, successful
    bounded poll, poll failure to `Failed`, idempotent stop, stop from `Failed`, destructor best-effort stop, probe error,
    start failure, and probe while running.
58. `Backend::poll()` returns `std::expected<void, BackendError>`. Success means one bounded Backend Poll Quantum
    completed; failure means runtime progress cannot continue. `PollStatus`, `WorkDone`, and `NoWork` are deleted because
    Runner never changed pacing or lifecycle behavior based on them. Backend activity facts stay private, and future
    Diagnostics uses meaningful backend-specific counters instead of a lifecycle activity bit. See ADR-0047.

Constraint:

- A synchronous `poll()` keeps lifecycle ownership visible while the eBPF backend is being adapted and the DPDK backend is still new.
- `BackendConfig` variant is selected from the validated top-level `Config`; backend implementations must reject the wrong variant as a typed programmer/configuration error instead of reading raw TOML.
- `BackendRunner` is the single place that enforces invalid lifecycle transitions. This prevents eBPF and DPDK implementations from drifting into different state-machine behavior.

Probe role:

- `probe()` is the pre-start capability gate. It is not a warm-up, not partial startup, and not a fallback mechanism.
- `probe()` is not a health check or readiness check. It does not describe runtime liveness after `start()`.
- eBPF examples: verify required kernel capabilities, usable BPF arena support, interface existence, and permissions that can be checked without attaching programs or creating production maps. BPF arena support may require a bounded create-and-close probe of a minimal arena map.
- DPDK examples: verify DPDK support is compiled/available and configured port identifiers look usable without binding ports or reserving runtime resources.
- Probe failures must be machine-readable and operator-readable. Example: `BackendErrorCode::Unsupported` plus `eBPF backend requires BPF arena support, but the target kernel does not provide it`.

## Segment 11: Runtime Loop Ownership

Decisions:

1. The first Host Runtime loop is a simple synchronous loop that repeatedly calls `poll()` until shutdown.
2. `poll()` is the canonical backend step name.
3. `poll()` executes one bounded, Backend-defined Poll Quantum. A quantum may include a bounded backend-native readiness
   wait, but never an unbounded wait or unbounded backlog drain. It reports only successful completion or typed failure.
4. Signal handling lives in a separate small process-control module.
5. Superseded by Segment 10 decision 58. `BackendRunner` deliberately checks only poll success or failure and immediately
   begins its next Stop Condition/poll iteration after success; a universal idle sleep would conflict with a DPDK PMD
   busy-poll loop.

Constraint:

- The Host Runtime loop owns backend sequencing: `probe()`, `start()`, repeated `poll()`, then `stop()`.
- The process-control module only turns process signals into shutdown requests. It must not own Config loading, Backend selection, Backend lifecycle, or Backend diagnostics.
- A Backend may use its native bounded readiness wait inside its Poll Quantum, as eBPF does, but its maximum wait and
  work bounds are part of the Backend interface. DPDK's Poll Quantum is nonblocking and performs bounded RX/TX bursts.
- Runner observes a Stop Request only between Poll Quanta, so every Backend must keep the quantum bounded and document
  its worst-case stop-observation latency.
- A successful quantum may process zero backend work; this remains normal and is not separately reported to Runner.

## Segment 12: Process-control Module

Decisions:

1. Process Control lives in an independent module.
2. Process Control exposes a `ProcessControl` C++ class, not only free functions.
3. `ProcessControl` is a process-wide singleton.
4. `SIGINT` and `SIGTERM` set a sticky Shutdown Request.
5. Repeated signals do not need to be counted.
6. Signal source does not need to be retained in the MVP.
7. Tests may verify shutdown request state directly without raising real process signals.
8. `install_signal_handlers()` returns `std::expected<void, ProcessControlError>`.
9. `ProcessControlErrorCode` starts with the minimum value `SignalInstallFailed`.
10. Test reset is not part of the public production API; tests use a dedicated access helper.
11. Signal handlers only write a `volatile sig_atomic_t` flag.
12. File layout is `src/process_control/process_control.h`, `process_control.cc`, `process_control_error.h`, and `process_control_test_access.h`, with tests in `tests/unit/process_control/`.
13. `install_signal_handlers()` is idempotent.
14. Process Control does not restore previous signal handlers in the MVP.
15. `ProcessControlError` carries a typed code, `std::error_code`, and human-readable message.

Constraint:

- Process Control must not own Config loading, Backend selection, Backend lifecycle, Backend diagnostics, or the Host Runtime polling loop.
- Test-only reset behavior must be explicit and must not become normal runtime control flow.

## Segment 13: Module-by-module Refactor Flow

Decisions:

1. The refactor proceeds by module, not by deciding every future subsystem up front.
2. The active design module is the only module grilled in detail.
3. Future DPDK, DNS cache semantics, and observability redesign decisions are deferred until their modules become active.

Current module:

- eBPF Backend module.

Next module candidate:

- Cache/DNS module.

## Segment 14: eBPF Backend Runtime Boundary

Decisions:

1. Module 7 replaces the legacy eBPF production runtime path with `EbpfBackend + BackendRunner`.
2. `BackendRunner` is the only production lifecycle controller. Production code drives backend lifecycle through `run(StopCondition&)` and reads `state() const noexcept`.
3. `BackendRunner::run()` is single-use per runner instance.
4. `StopCondition` lives in `src/backend/stop_condition.h`.
5. `ProcessControl` directly implements `StopCondition` in the MVP and depends only on the stop-condition contract.
6. Module 7 `StopReason` starts with `Signal`, `Manual`, and `Timeout`.
7. `ShutdownReport` preserves the accepted `StopRequest` for normal successful shutdown.
8. A successful `ShutdownReport` can carry `Signal`, `Manual`, or `Timeout`; all three are normal shutdown reasons rather than backend failures.
9. If `stop()` fails after an accepted Stop Request, `BackendRunner::state()` becomes `Failed`.
10. If `poll()` returns a backend error, `BackendRunner::run()` does not poll `StopCondition` again; it performs best-effort `stop()` and returns the original backend error.
11. If `BackendRunner::run()` is called while the runner state is not `Created`, it returns `BackendErrorCode::InvalidState`.
12. If a Stop Request already exists before backend startup, `BackendRunner::run()` returns `ShutdownReport` without starting the backend and sets `state()` to `Stopped`.
13. Module 7 production composition stays in `main.cc`: load Config, call `make_backend(const Config&)`, construct `BackendRunner`, and call `run(process_control)`.
14. Process Control keeps static methods for signal-handler-facing operations, but adds an instance `poll()` implementation for `StopCondition`.
15. Production code must not call Process Control static methods through a `ProcessControl` instance.
16. `StopCondition` has a virtual destructor.
17. `StopReason` and `StopRequest` live in `src/backend/stop_condition.h` with `StopCondition`.
18. `ShutdownReport` uses the field name `accepted_stop` for the accepted Stop Request.
19. Backend runner tests exercise `run()` and `state()` as the public contract and use fake backend traces for private hook sequencing instead of calling private lifecycle methods directly.
20. `EbpfBackend` owns current C loader state through `std::unique_ptr<bpf_ctx>`, with the complete C struct kept out of public backend/runtime APIs.
21. `bpf_ctx` and operations that traffic directly in it are transitional refactor targets after Module 7 establishes the C++ backend production path.
22. eBPF probe fakes live in the same private `EbpfLoaderOps` table; Module 7 does not introduce a separate `EbpfProbeOps`.
23. Module 7 has no `BackendFactory` class. Backend creation is represented by the `make_backend(const Config&)` free function.
24. Superseded: `Config::backend` is the selected `BackendConfig` variant, so backend selection and backend-specific
    configuration cannot disagree. `make_backend(const Config&)` dispatches directly on that alternative.
25. `EbpfBackend` unit tests use fake `EbpfLoaderOps` to cover probe/start/poll/stop behavior without root, BPF attachment, real interfaces, BPF arena support, or kernel feature availability.
26. `EbpfLoaderOps` may expose `bpf_ctx*` in function signatures, but only inside the private eBPF backend boundary.
27. `EbpfLoaderConfig` is a temporary private adapter shape with only `iface`, `arena_pages`, and `cleanup_interval_ms`.
28. Module 7 treats `loader_cleanup_bpf()` as successful because the current C API returns `void`; typed cleanup failure is deferred to the eBPF loader resource/RAII refactor.
29. `EbpfBackend::poll()` owns warnings for non-fatal BPF log-ring poll errors and then continues packet-ring polling.
30. Production code outside `make_backend()` does not directly construct `EbpfBackend`; eBPF-specific tests may directly construct it with fake `EbpfLoaderOps`.
31. Module 7 does not use friend-only constructors or passkey construction to enforce the production-only `make_backend()` rule.
32. `EbpfLoaderOps` is a static-storage function table, and `EbpfBackend` stores a non-owning pointer or reference to it.
33. `EbpfBackend` destructor does not call `stop()`; lifecycle cleanup remains runner-managed.
34. `probe()` remains part of the `Backend` lifecycle interface and is called by `BackendRunner`; `make_backend(const Config&)` does not perform host capability probing.
35. `ShutdownReport` carries only the accepted Stop Request in Module 7; backend-specific shutdown metadata belongs to future diagnostics/observability work.
36. `BackendError` remains `code + message + optional std::error_code cause` in Module 7; no backend-specific detail maps or variants are added.
37. Superseded by Segment 10 decision 58. Module 7 originally retained `WorkDone`/`NoWork`; the shared interface now
    reports only quantum success or typed failure.
38. `StopReason::Signal` means Process Control observed a supported process-termination signal.
39. `StopReason::Manual` means an in-process control source explicitly requested an orderly shutdown; it is not a backend failure.
40. `StopReason::Timeout` means a Stop Condition's configured runtime deadline elapsed; it is not a backend poll timeout, loader-operation timeout, or backend failure.
41. Module 7 defines Manual and Timeout reason semantics but does not add production Stop Condition implementations for either reason.
42. If a backend runtime error occurs, successful best-effort cleanup does not erase the failure; `BackendRunner::state()` remains `Failed`.
43. `BackendRunner` may be constructed with a null backend; `run()` reports `BackendErrorCode::InvalidState` instead of asserting or throwing.
44. `stop_reason_name(StopReason) noexcept` is the canonical Stop Reason text conversion.
45. `main.cc` does not print a successful `ShutdownReport` in Module 7 and returns exit code `0`; successful-shutdown diagnostics are deferred to the Runtime Diagnostics/Logging Module.
46. `BackendRunner` has a private `backend_active_` flag independent of public lifecycle state. It tracks whether the runner still owes the backend a stop attempt, allowing cleanup to complete while the lifecycle outcome remains `Failed`.
47. After any `Backend::start()` failure, `BackendRunner` calls `Backend::stop()`. The backend inspects its own local resource state and cleans resources acquired during partial startup; the runner does not inspect backend-specific state.
48. A null backend makes `run()` return `BackendErrorCode::InvalidState` and changes `BackendRunner::state()` to `Failed`.
49. `EbpfLoaderOps` receives a per-backend non-owning context pointer. Tests keep trace/results in fixture-owned contexts rather than global mutable fake state.
50. The private runner cleanup flag keeps the name `backend_active_`. It means the runner entered the backend start boundary and has not yet completed a successful stop; it does not assert that the backend is currently `Running`.
51. If start fails and cleanup also fails, `run()` preserves and returns the original start error, keeps state `Failed`, and does not add suppressed-error support.
52. `run()` attempts stop once after a start or runtime failure. A failed stop remains pending through `backend_active_`, and the destructor performs one additional best-effort attempt without further retries.
53. The `EbpfLoaderOps` context is a non-owning `void*` passed to every operation. Production may use `nullptr`; a test context must outlive its `EbpfBackend`.
54. Backend lifecycle virtual functions remain non-`noexcept`, but operational failures must use `std::expected`; throwing violates the Backend contract. `BackendRunner` does not catch lifecycle-hook exceptions, and an exception escaping `stop()` during the runner's `noexcept` destruction terminates the process.
55. `StopCondition::poll()` is non-const `noexcept` and returns `std::optional<StopRequest>`.
56. Each eBPF probe operation returns `std::expected<bool, std::error_code>`. `false` represents a completed negative check, while `std::unexpected` represents failure to perform the check; `EbpfBackend` alone maps both forms to `BackendError`.
57. `BackendError::cause` is set only when an operation contract explicitly identifies an errno or `std::error_code`. Private C loader sentinels and ambiguous mixed-domain negative returns stay in the message and leave `cause` empty.

Constraint:

- Stop-source expansion after Module 7 must not weaken the lifecycle ownership rule: stop requests request shutdown, but `BackendRunner::run()` remains the only production path that executes backend stop.

## Segment 15: Runtime Diagnostics/Logging Deferral

Decisions:

1. The current codebase lacks a unified runtime diagnostics/logging boundary.
2. Module 7 does not introduce a process-global singleton logger.
3. Module 7 may emit minimal local warnings for non-fatal eBPF backend conditions, such as log-ring poll errors, while low-level C boundary diagnostics remain temporarily in the C loader.
4. Runtime diagnostics/logging becomes its own module after eBPF and DPDK backend boundaries stabilize and before the full test-suite rewrite.
5. The future diagnostics/logging module should evaluate explicit diagnostics sinks or dependency injection before considering a singleton logger.
6. Module 9 selects pinned `spdlog` 1.17.0 and may use it for minimal synchronous DPDK lifecycle logging. This narrows
   Module 10's implementation choice without moving common routing, formatting, or existing-output migration out of
   Module 10. Module 9 deliberately uses spdlog's process-global convenience API instead of adding logger injection;
   Module 10 may replace that access model when it designs the common boundary.

Constraint:

- Runtime diagnostics/logging must not become a replacement for typed `std::expected` errors, and it must not reintroduce the deleted Observability Surface unless that future surface is explicitly scoped.

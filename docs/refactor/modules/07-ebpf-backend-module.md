# Module 7: eBPF Backend Module

Goal:

- Wrap existing eBPF behavior behind the Backend interface.

Scope:

- Place the eBPF backend implementation in `src/backend/ebpf/`.
- Preserve the existing eBPF dataplane and C loader behavior. Module 7 wraps the current loader API instead of rewriting `src/core/loader.c` as C++.
- Do not migrate `src/core/loader.c` to C++ in Module 7. Reassess that migration after the production path runs through `EbpfBackend + BackendRunner`.
- Replace `shinku_run_legacy_ebpf()` with `EbpfBackend + BackendRunner` as the production runtime path.
- Do not keep `shinku_run_legacy_ebpf()` as a production fallback path.
- Production runtime calls `make_backend(const Config&)`; direct `EbpfBackend(EbpfConfig, CacheConfig)` construction is not allowed in production code outside the `make_backend()` implementation.
- eBPF-specific tests may directly construct `EbpfBackend` with fake `EbpfLoaderOps`.
- `make_backend(const Config&)` returns `std::expected<std::unique_ptr<Backend>, BackendError>`.
- Add the production backend creation function in `src/backend/backend_creation.h` and `src/backend/backend_creation.cc`.
- `make_backend(const Config&)` is a free function only; Module 7 does not introduce a `BackendFactory` class.
- `make_backend(const Config&)` returns `BackendErrorCode::Unsupported` when the selected backend is not yet implemented, even if the Config itself is valid.
- `Config::backend` stores exactly one selected backend-config alternative, and `make_backend(const Config&)` dispatches
  directly on it; there is no separate selector/config consistency check.
- `BackendRunner` is the only production lifecycle controller. Production code must not call concrete backend lifecycle methods directly.
- `Backend` lifecycle methods are runner-owned implementation hooks. Direct concrete backend construction/calls are reserved for `make_backend()` implementation code and backend-specific tests.
- Module 7 does not use friend-only constructors or passkey construction to enforce the production-only `make_backend()` rule. It relies on keeping `ebpf_backend.h` as an eBPF-private header and keeping production composition outside `make_backend()` on the abstract `Backend` API.
- `BackendRunner` public API only exposes `run(StopCondition&)` and `state() const noexcept`. `probe()`, `start()`, `poll()`, and `stop()` are runner-private implementation details.
- `BackendRunner::run()` is single-use per `BackendRunner` instance. A runner does not reset for a second production lifecycle.
- `probe()` remains part of the `Backend` lifecycle interface and is called by `BackendRunner`; `make_backend(const Config&)` constructs the selected backend but does not perform host capability probing.
- Do not introduce a cache base class in Module 7. Keep backend-neutral `CacheConfig` for shared DNS cache policy and use backend-specific config sections for storage/resource knobs.
- `EbpfBackend` is constructed from `EbpfConfig` plus backend-neutral `CacheConfig`.
- `EbpfBackend` relies on `BackendRunner` as the lifecycle state-machine authority. `EbpfBackend` performs only local resource-safety checks and must not duplicate the full runner state machine or own stop policy.
- `BackendRunner` calls `Backend::stop()` after any `Backend::start()` failure. The runner does not inspect concrete backend resources; each backend uses its internal resource state to clean up everything acquired before the failure.
- `Backend::stop()` must be safe after no start, partial start, successful start, and an earlier stop. With no acquired resources it returns success without calling loader cleanup; after partial start it releases only the resources that were acquired.
- `Backend::probe()`, `start()`, `poll()`, and `stop()` remain non-`noexcept` virtual functions. Operational failures must still be returned through `std::expected`; throwing from a lifecycle hook violates the Backend contract.
- `BackendRunner` does not catch exceptions from Backend lifecycle hooks. Its `noexcept` destructor makes the documented best-effort stop call without a catch block, so an exception escaping `Backend::stop()` during destruction terminates the process.
- `EbpfBackend` destructor does not call `stop()`. Lifecycle cleanup is runner-managed; the backend destructor only releases C++-owned memory that was not handed to the C loader lifecycle.
- Module 7 preserves the legacy eBPF privilege baseline: root, or effective `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_SYS_ADMIN`. Missing required privileges map to `BackendErrorCode::PermissionDenied`.
- `EbpfBackend` receives `CacheConfig`, but Module 7 only maps fields the current C loader can express. Cache fields that cannot be represented by the current eBPF loader do not change eBPF behavior until the Cache/DNS Module.
- Add a private transitional `EbpfLoaderConfig` in `src/backend/ebpf/` as the eBPF backend-to-loader configuration shape.
- `EbpfLoaderConfig` is a temporary private adapter shape with only `iface`, `arena_pages`, and `cleanup_interval_ms`.
- Add a private `EbpfLoaderOps` function table in `src/backend/ebpf/` so `EbpfBackend` unit tests can fake loader/probe/poll/cleanup calls without root, BPF attachment, or kernel feature dependencies.
- `EbpfLoaderOps` may expose `bpf_ctx*` in its function signatures, but only inside the private eBPF backend boundary.
- `EbpfLoaderOps` is a static-storage function table. `EbpfBackend` stores a non-owning pointer or reference to it.
- `EbpfLoaderOps` uses a non-owning `void* context` passed to every operation. Production may pass `nullptr`; tests pass fixture-owned state that must outlive the `EbpfBackend` using it.
- eBPF probe fakes live in the same `EbpfLoaderOps` table; Module 7 does not introduce a separate `EbpfProbeOps`.
- `EbpfLoaderOps` and its fake-test seam live in a single private `src/backend/ebpf/ebpf_loader_ops.h` header.
- Each `EbpfLoaderOps` capability check returns `std::expected<bool, std::error_code>`: `true` means the check passed, `false` is a successful negative capability/configuration conclusion, and `std::unexpected` means the check itself failed.
- `EbpfBackend` owns the translation from probe-operation results to `BackendError`: a negative privilege conclusion maps to `PermissionDenied`, a missing interface maps to `WrongConfig`, and an unsupported arena maps to `Unsupported`; an operation error from any of these checks maps to `ProbeFailed` with its `std::error_code` as `cause`.
- Production `EbpfLoaderOps` converts `EbpfLoaderConfig` to the current C `struct env` internally before calling `loader_setup_bpf()`.
- Keep `struct env` temporarily as the C loader bridge, but move conversion out of public `src/config/legacy_env_adapter.*` into the private eBPF backend boundary.
- Do not expose `struct env` through `EbpfBackend`, `BackendRunner`, `make_backend()`, runtime loop APIs, or eBPF backend tests except tests that explicitly target the transitional C loader adapter.
- Delete the public `src/config/legacy_env_adapter.*` API after eBPF Backend owns eBPF lifecycle.
- `EbpfBackend` owns the current C loader state through `std::unique_ptr<bpf_ctx>`, with the complete `bpf_ctx` definition included only from eBPF backend implementation files.
- `bpf_ctx` and operations that traffic directly in it are transitional refactor targets. Module 7 hides them from public backend/runtime APIs; later eBPF loader refactors should replace this C loader state with C++ resource-owning structures.
- `poll()` polls the BPF log ring and packet ring once per call, preserving the old loop's behavior as closely as possible.
- Module 7 keeps the old poll pacing inside `EbpfBackend::poll()`: log ring timeout `100ms`, then packet ring timeout `100ms`.
- Positive event counts remain private and `poll()` returns success.
- Log ring `-EINTR` maps to successful quantum completion.
- BPF log ring poll errors are non-fatal: `EbpfBackend::poll()` logs a warning and continues to packet ring polling.
- Packet ring `-EINTR` maps to successful quantum completion.
- Packet ring negative errors other than `-EINTR` map to `BackendErrorCode::PollFailed`; `BackendRunner` then moves to `Failed`.
- Preserve BPF build, skeleton generation, attach/detach, ring polling, cache cleanup, and existing behavior tests.
- If BPF arena is unavailable, selected eBPF backend fails as unsupported. Do not introduce compatible-store fallback.
- `EbpfBackend::start()` calls `loader_setup_bpf()` and `loader_start_cleanup_thread()`.
- `EbpfBackend::probe()` checks the privilege baseline before probing BPF feature support; insufficient required privileges map to `BackendErrorCode::PermissionDenied`.
- `EbpfBackend::probe()` checks in this order: privilege baseline, interface existence, then BPF arena map-type support.
- `EbpfBackend::probe()` checks interface existence with `if_nametoindex()`; a missing interface maps to `BackendErrorCode::WrongConfig`.
- eBPF `probe()` checks BPF arena support with `libbpf_probe_bpf_map_type(BPF_MAP_TYPE_ARENA, nullptr)` when available. If that API is unavailable for the target build, it may fall back to a bounded transient capability probe by creating and immediately closing a minimal `BPF_MAP_TYPE_ARENA` map.
- Production `EbpfLoaderOps` converts `libbpf_probe_bpf_map_type(BPF_MAP_TYPE_ARENA, nullptr) == 0` to the successful negative result `false`; `EbpfBackend` maps it to `BackendErrorCode::Unsupported`.
- Production `EbpfLoaderOps` converts a negative `libbpf_probe_bpf_map_type(BPF_MAP_TYPE_ARENA, nullptr)` result to `std::unexpected(std::error_code)`; `EbpfBackend` maps it to `BackendErrorCode::ProbeFailed`. The diagnostic message may also retain the raw libbpf return value.
- eBPF `probe()` must not attach programs, open/load the production skeleton, spawn threads, mmap the arena, start packet processing, or retain resources.
- If `loader_setup_bpf()` fails, `EbpfBackend::start()` returns `BackendErrorCode::StartFailed` with the raw loader return value. The current C setup failure path has already called `loader_cleanup_bpf()`, so the subsequent runner-owned `stop()` observes that no loader resources remain and is a no-op.
- If `loader_start_cleanup_thread()` fails after successful setup, `EbpfBackend::start()` returns `BackendErrorCode::StartFailed` while retaining enough internal resource state for the subsequent runner-owned `stop()` to call `loader_cleanup_bpf()`.
- Because current `loader_cleanup_bpf()` returns `void`, Module 7 treats cleanup as successful. Typed cleanup failure is deferred until the eBPF loader resource/RAII refactor gives cleanup operations reportable errors.
- Module 7 maps all `loader_setup_bpf()` failures to `BackendErrorCode::StartFailed`; it does not expose or reinterpret private C loader error codes.
- Cleanup thread startup failure is fatal and maps to `BackendErrorCode::StartFailed` because cleanup scheduling is a backend-critical Operational Loop.
- Until the DPDK Backend Module exists, selecting DPDK through `make_backend(const Config&)` returns `BackendErrorCode::Unsupported`.
- `StopCondition` lives in `src/backend/stop_condition.h`.
- `StopCondition` is an interface with a virtual destructor.
- `StopReason` and `StopRequest` are defined in `src/backend/stop_condition.h` with `StopCondition`.
- `src/backend/stop_condition.h` declares `std::string_view stop_reason_name(StopReason) noexcept` as the canonical text conversion for runner errors and future diagnostics.
- `ProcessControl` directly implements `StopCondition` in the MVP and depends only on `backend/stop_condition.h`, not on `BackendRunner` or concrete backends.
- `BackendRunner` owns the runtime loop through `run(StopCondition&)`.
- `StopCondition::poll()` is non-const `noexcept` and returns `std::optional<StopRequest>` so stateful stop sources may update internal state while being polled.
- `StopReason` starts with `Signal`, `Manual`, and `Timeout`.
- `StopReason::Signal` means Process Control observed a supported process-termination signal.
- `StopReason::Manual` means an in-process control source explicitly requested an orderly shutdown; it does not represent a backend failure.
- `StopReason::Timeout` means a Stop Condition's configured runtime deadline elapsed; it does not represent a backend poll timeout, loader-operation timeout, or backend failure.
- Module 7 does not add production Manual or Timeout Stop Condition implementations. It defines their reason semantics now so future stop sources do not need to change the runner result contract.
- `StopRequest` MVP contains only `StopReason reason`.
- `ProcessControl::poll()` is sticky: after shutdown is requested, each call returns `StopReason::Signal` until test-only reset.
- `ProcessControl` keeps static signal-handler-facing methods such as `request_shutdown()`, `shutdown_requested()`, and `install_signal_handlers()`, but adds an instance `poll()` implementation for `StopCondition`.
- Production code must not call Process Control static methods through a `ProcessControl` instance.
- A future manual stop source is modeled as a `StopCondition` implementation that exposes a request method such as `request_stop()` and later returns `StopReason::Manual` from `poll()`.
- Manual stop request methods must not call `BackendRunner::stop()` or backend `stop()` directly; `BackendRunner::run()` remains the only place that executes backend stop in the production run path.
- A future timeout stop source owns its deadline and returns `StopReason::Timeout` from `poll()` once that deadline has elapsed. It must not execute backend stop directly.
- `ShutdownReport` is defined in `src/backend/backend_runner.h`.
- `BackendRunner::run()` returns `std::expected<ShutdownReport, BackendError>`, where `ShutdownReport` includes only `StopRequest accepted_stop` in the MVP.
- `ShutdownReport` is the normal successful result for an accepted `Signal`, `Manual`, or `Timeout` Stop Request. Defining a reason does not require Module 7 to provide a production Stop Condition that emits it.
- `ShutdownReport` does not carry backend-specific shutdown metadata such as event counts, packet counts, cleanup counts, or backend-specific payload variants. Such data belongs to a future diagnostics/observability design, not the lifecycle result.
- `BackendError` remains `code + message + optional std::error_code cause` in Module 7. Do not add backend-specific detail maps or variants.
- `BackendError::cause` is populated only when the source operation's contract identifies a value as an errno or `std::error_code`. A negative integer alone is insufficient evidence.
- Private C loader sentinel values such as `ERR_SKEL_LOAD`, `ERR_RB_CREATE`, and `ERR_INVALID_IFACE` stay in the human-readable error message and leave `cause` empty. Mixed return domains such as `loader_setup_bpf()` must not guess an errno from the raw negative value. An operation with an explicit errno contract, such as the `pthread_create()` result used by cleanup-thread startup, may populate `cause` with the corresponding generic-category error code.
- ADR-0047 later removes `PollStatus`; event counts remain private and backend-specific work categories belong to
  Diagnostics rather than the lifecycle interface.
- `BackendRunner::run()` starts the backend, polls until a `StopRequest` or backend error, and calls `stop()` when a stop is requested.
- If `run()` is called after a stop request already exists, it returns `ShutdownReport` without starting the backend and sets `state()` to `Stopped`.
- If `run()` is called while the runner state is not `Created`, it returns `BackendErrorCode::InvalidState`.
- `BackendRunner` construction accepts a null `std::unique_ptr<Backend>` without throwing or asserting. `run()` detects the missing backend, moves the runner state to `Failed`, and returns `BackendErrorCode::InvalidState`.
- `BackendRunner` has a private `backend_active_` flag, separate from public `BackendState`. It means the runner still owes the backend a `stop()` attempt; it does not mean the backend is successfully `Running`.
- The name `backend_active_` is retained, with the precise meaning that the runner has entered the backend start boundary and has not yet completed a successful stop. It may therefore be true during partial startup or failed cleanup as well as while `state() == Running`.
- `backend_active_` becomes true immediately before calling `Backend::start()`. A successful `Backend::stop()` clears it, including cleanup after start or poll failure. A failed stop leaves it true so the destructor may retry once.
- `BackendRunner` destructor performs best-effort stop only when `backend_active_` is true. This prevents duplicate stop calls after an error was already cleaned up while preserving `state() == Failed` as the lifecycle outcome.
- After `start()` succeeds, `BackendRunner::run()` checks `StopCondition` once before entering the poll loop.
- If `run()` succeeds, `BackendRunner::state()` becomes `Stopped`.
- If `stop()` fails after a `StopRequest`, `BackendRunner::state()` becomes `Failed`.
- If `stop()` fails after a `StopRequest`, `BackendRunner::run()` returns `BackendErrorCode::StopFailed` with context for both the stop reason and stop failure.
- If `poll()` returns a backend error, `BackendRunner::run()` does not poll `StopCondition` again; it performs best-effort `stop()` and returns the original backend error.
- If `start()` fails and the subsequent runner-owned `stop()` also fails, `run()` returns the original start error, keeps `state() == Failed`, and leaves `backend_active_` true. Module 7 does not replace the start error with `StopFailed` or attach the stop error as a suppressed error.
- `run()` makes only one stop attempt for a given start or runtime failure. It does not immediately retry a failed stop; the destructor makes one additional best-effort attempt when `backend_active_` remains true, then destruction proceeds regardless of that result.
- A backend runtime error determines the lifecycle outcome: `BackendRunner::state()` remains `Failed` after best-effort cleanup succeeds. Successful cleanup must not turn the outcome into `Stopped`.
- The original poll error is preserved as a local value inside `run()`; Module 7 does not store it as runner state and does not add suppressed-error support to `BackendError`.
- Backend lifecycle failures are returned as `BackendError`; `main.cc` owns printing `BackendError::message` and mapping it to a process exit code.
- Module 7 production composition stays in `main.cc`: parse CLI, load Config, install signal handlers, call `make_backend(const Config&)`, construct `BackendRunner`, and call `run(process_control)`.
- Process exit codes remain narrow in Module 7: CLI parse error returns `2`; config, process-control, backend creation, and backend runtime errors return `1`; help, version, and successful shutdown return `0`.
- `main.cc` does not print the successful `ShutdownReport` or shutdown reason in Module 7; it returns exit code `0`. Operator-facing successful-shutdown diagnostics are deferred to the Runtime Diagnostics/Logging Module.
- Delete `src/runtime/legacy_ebpf_runner.c` and `src/runtime/legacy_ebpf_runner.h` from Module 7 production build instead of keeping a debug or fallback entrypoint.
- Delete public `src/config/legacy_env_adapter.h` and `src/config/legacy_env_adapter.cc`; the only remaining `struct env` conversion belongs to the private eBPF loader adapter.
- A successful empty quantum does not add an extra runtime sleep in Module 7; the backend poll timeout remains the
  pacing mechanism.
- `EbpfBackend::stop()` only performs backend resource cleanup and does not print operator-facing lifecycle messages.
- Module 7 removes old production-path console lifecycle output such as "BPF System Running", "Shutting down", and "Cleanup thread stopped" from the C++ production path. Low-level loader/libbpf/cache diagnostics may remain in the C boundary until a later diagnostics module.

Verification:

- eBPF build succeeds.
- Backend runner tests cover `run()` and `state()` as the public contract. They do not call runner-private lifecycle steps directly; fake backend traces verify hook sequencing.
- Backend runner tests cover null-backend rejection, canonical Stop Reason names, accepted `Signal`/`Manual`/`Timeout` requests, and preservation of `Failed` after runtime-error cleanup.
- Backend runner tests verify that start failure triggers backend stop, successful failure cleanup is not repeated by the destructor, failed cleanup remains eligible for a destructor retry, and null backend changes state to `Failed`.
- Backend runner test fakes obey the non-throwing operational contract even though Backend lifecycle virtual functions are not declared `noexcept`; compile-time checks verify that `StopCondition::poll()` is `noexcept`.
- `EbpfBackend` tests use fake `EbpfLoaderOps` to cover eBPF probe/start/poll/stop mapping without requiring root, BPF attachment, a real interface, BPF arena support, or kernel feature availability.
- `EbpfBackend` tests distinguish each probe check's `false` result from its `std::unexpected(std::error_code)` result and verify the resulting `BackendErrorCode` and optional `cause`.
- `EbpfBackend` tests verify that private loader sentinel failures do not become `BackendError::cause`, while explicitly identified system error codes do.
- Each `EbpfBackend` stores a non-owning `void*` ops context alongside the static `EbpfLoaderOps` table. Every operation receives that context; production may use `nullptr`, while tests use fixture-owned contexts for independent traces and configured results without global mutable fake state. Tests ensure the context outlives the backend.
- Existing parser/cache/eBPF-relevant tests pass where host capabilities allow.

Result:

- Added `StopCondition`, Stop Requests, canonical Stop Reason names, and the runner-owned `run()` loop. `BackendRunner` now exposes only `run()` and `state()` and preserves the documented cleanup/error semantics.
- Made Process Control implement `StopCondition` directly while retaining static signal-handler operations.
- Added the private `EbpfLoaderConfig` and context-aware `EbpfLoaderOps` seam, production privilege/interface/arena probes, `EbpfBackend`, and the `make_backend(const Config&)` free function.
- Replaced the production legacy runner path in `main.cc` with `make_backend() + BackendRunner`, removed the public legacy Config adapter and legacy runtime runner, and kept the temporary C `env` type inside the loader boundary.
- Added focused Backend Runner and eBPF Backend tests for lifecycle sequencing, cleanup retries, Stop Reasons, probe mapping, loader-error causes, partial startup, ring polling, backend-alternative dispatch, and unsupported DPDK behavior.
- `meson compile -C build` passed.
- `meson compile -C /tmp/shinku-build-bpf-log shinku xdp_pass.bpf.o` passed with `bpf_log=true`; generated `vmlinux.h` warnings remain unchanged.
- `ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1 meson test -C build 'Backend Runner Test' 'Process Control Test' 'eBPF Backend Test' --no-rebuild --print-errorlogs` passed all three focused tests. Leak detection is disabled because LeakSanitizer cannot run under the current ptrace environment; AddressSanitizer remains enabled.
- The full non-root Meson run passed 9 of 12 tests. The two arena tests still require root, and the legacy Cache Store Correctness Test still has its existing no-root `slot_owners` failures.
- `meson compile -C build tidy` remains blocked by existing BPF-header clang-tidy errors; an additional direct clang-tidy pass over the new C++ production sources found no new actionable diagnostics after fixes.
- Root-required attach/detach integration and soak tests were not run in this environment.

# Confirmed Refactor Decisions

## Starting Point

The refactor starts from `master` on branch `refactor`, not from an empty tree. The existing C code contains behavior that should be treated as regression assets: DNS parsing, cache admission/eviction, ECS handling, negative caching, BPF arena safety, and tests.

## Known Goals

- Move all Host Runtime `.c` files to `.cc` over the refactor.
- Use C++23 for the Host Runtime: Meson should set `cpp_std=c++23`.
- Keep C where required by eBPF, kernel-facing code, generated BPF skeletons, or deliberately small C ABI boundaries.
- Add a DPDK Backend behind a C++ Cache Engine abstraction.
- Keep the current eBPF Backend runnable throughout the refactor.
- If the selected eBPF Backend is unsupported on the target kernel, such as missing usable BPF arena support, startup fails with an unsupported-backend error. There is no compatible-store fallback.
- Delete the current Observability Surface completely: degraded mode, runtime event bus, `/healthz`, `/readyz`, Prometheus metrics, BPF counters, Grafana/Prometheus files, and observability tests.
- Represent runtime parameters with a TOML Config File selected by a thin subcommand. Full CLI parsing is deferred and kept only as a future extension point.
- Add a runtime diagnostics/logging boundary after backend boundaries stabilize; do not let ad hoc `printf()`/`fprintf()` calls become the long-term architecture.

## Current Code Facts

- `src/core/loader.c` currently owns eBPF lifecycle, ring polling, and cleanup thread lifecycle.
- `src/core/dns_parser.c` performs response validation and cache insertion without the deleted observability counters.
- `src/core/cache_types.h` no longer carries observability state inside cache context.
- `src/bpf/cache.bpf.c` no longer contains BPF-side observability counters or sampling configuration.
- `meson.build` and `meson.options` no longer expose observability build flags.
- Tests include behavior tests that should be preserved; observability-specific tests have been deleted.

## Candidate Work Slices

1. Establish build and test baseline on `refactor`.
2. Remove the current Observability Surface while preserving eBPF operational loops.
3. Introduce C++ build support without changing eBPF behavior.
4. Introduce the C++ Config domain model and TOML Config File loader before DPDK backend implementation.
5. Keep `src/cli` as a thin config-selector subcommand rather than the full configuration authority.
6. Convert Host Runtime modules from `.c` to `.cc` incrementally.
7. Define the C++ Cache Engine interface and backend-neutral DNS/cache types.
8. Split common DNS/cache policy from eBPF-specific loader/storage.
9. Implement DPDK Backend while keeping the eBPF Backend runnable.
10. Introduce a runtime diagnostics/logging boundary after backend runtime paths stabilize.
11. Reintroduce a cleaner Observability Surface later only if explicitly scoped.

## Decision Cadence

The refactor is designed and implemented module by module. Grill questions should stay scoped to the current module and avoid forcing decisions for later modules before their code boundary is being designed.

## Grill Queue

### Segment 1: Refactor Scope

Decisions:

1. All Host Runtime `.c` files should gradually become `.cc`.
2. The current Observability Surface is deleted in full, including degraded mode, runtime event bus, health/readiness endpoints, Prometheus metrics, BPF counters, dashboard files, and observability tests.
3. The current eBPF Backend must remain runnable during the refactor.

Constraint:

- Deleting observability must not delete backend-critical Operational Loops. Ring-buffer packet polling, cleanup scheduling, signal handling, and eBPF attach/detach remain product behavior, not observability.

### Segment 2: C++ Standard and Migration Order

Decisions:

1. Meson targets `cpp_std=c++23`, not compiler-tracking `c++2c`.
2. A new C++ domain model is introduced before DPDK backend implementation.
3. The first practical C++ slice is the Config domain model and TOML Config File loader. `src/cli` is deferred as a thin config-selector subcommand.

Constraint:

- The first C++ conversion must keep the current eBPF backend runnable. The TOML loader may call existing C loader/config code through a temporary C Boundary until the lifecycle/domain model is ready.

### Segment 3: C++ Domain Model Boundary

Decisions:

1. The first domain model slice covers `Config` and `Backend Lifecycle` only.
2. Host Runtime operations return `std::expected<T, Error>` or typed status objects, not exceptions and not raw errno.
3. The domain model uses new C++ types immediately. The current eBPF Backend is connected through adapters rather than becoming the shape of the new model.

Constraint:

- `CacheKey`, `CacheValue`, and DNS parser result types are intentionally deferred. Pulling them into the first slice would couple the C++ migration to DNS semantic changes and make it harder to keep eBPF runnable.

### Segment 4: Backend Lifecycle State Machine

Decisions:

1. The public lifecycle state machine is simple: `Created -> Running -> Stopped -> Failed`.
2. `probe()` is a pre-start capability check with no persistent side effects. It answers whether the selected Backend is supported on the current host with the validated Config.
3. Backend selection is fixed at startup for the whole process lifetime. Runtime backend switching is out of scope.

Constraint:

- `probe()` can inspect system capabilities and configuration validity, and it may perform bounded transient capability probes that immediately release resources. It must not reserve hugepages, bind NIC ports, create production BPF maps, open BPF skeletons, spawn threads, attach programs, start packet processing, retain resources, or mutate process/global state.
- The Host Runtime calls `probe()` after Config Loader succeeds and before `start()`.
- If `probe()` reports an unsupported selected Backend, startup fails. The system does not switch to another Backend and the eBPF Backend does not fall back to a compatible store when BPF arena is unavailable.

### Segment 5: Config Model for `src/cli`

Decisions:

1. Introduce a new Config Schema instead of preserving the old CLI shape as the canonical model.
2. Configuration source is a TOML Config File. CLI/env configuration is out of scope for this phase.
3. Use one top-level `Config` type with optional `ebpf` and `dpdk` Backend Sections, plus validation.
4. Cache Policy belongs in a top-level backend-neutral `cache` section.
5. Config implementation lives in independent `src/config/`; `src/cli` does not own Config parsing.
6. Config Module uses the file layout `config.h`, `config_error.h`, `diagnostic_sink.h`, `toml_loader.h`, and `toml_loader.cc`.
7. Config Module exposes `std::expected<Config, ConfigError> load_config(const std::filesystem::path& path, DiagnosticSink& sink)`.
8. Config Module temporarily provides `to_legacy_env(const Config&)` to keep the existing eBPF loader runnable before the eBPF Backend Module lands.
9. Config Module performs only minimum hard validation in the first implementation.
10. Returned `Config` retains only the selected backend's parsed config and backend-neutral `CacheConfig`.
11. TOML schema fields have no defaults in the MVP; field defaults are deferred to a later optimization pass.
12. Config Loader emits unknown-key warnings before hard validation and returns on the first hard validation error.
13. Config diagnostics for schema and validation issues include TOML field paths.
14. `ConfigErrorCode` includes `FileNotFound`, `ReadError`, `ParseError`, `SchemaError`, `ValidationError`, and `UnsupportedBackend`.
15. `ConfigError` retains the Config File path when available.
16. Config Loader opens the provided path directly without a preflight `exists()` check.

Constraint:

- Validation must reject missing configuration for the selected backend and reject contradictory configuration when it would make startup ambiguous. Backend-specific sections may exist, but only the selected backend's section is required to be complete. Cache Policy applies equally to eBPF and DPDK unless a future ADR explicitly permits backend-specific overrides.
- `src/cli` may select a Config File path, but it must not contain TOML schema knowledge or replace the Config Loader.

### Segment 6: Config Source Compatibility

Decisions:

1. The configuration file is selected by a thin launch subcommand.
2. The canonical backend selector is the TOML field `backend = "ebpf" | "dpdk"`.
3. Env vars are not supported.
4. Old eBPF CLI flags do not need deprecated aliases. The refactor may break old CLI compatibility immediately.
5. CLI MVP accepts only `shinku run` and `shinku run --config path/to/file.toml`.
6. CLI MVP rejects unsupported forms such as `shinku --config path`, `shinku run -c path`, and `shinku run --backend ebpf`.
7. CLI owns CLI syntax diagnostics; Config Loader owns Config File diagnostics.
8. CLI parser returns a typed `CliCommand` containing the selected Config File path.
9. CLI Module uses the file layout `cli.h`, `cli.cc`, and `main.cc`.
10. `CliErrorCode` MVP contains `MissingSubcommand`, `UnsupportedSubcommand`, `MissingConfigPath`, `UnsupportedOption`, and `UnexpectedArgument`.
11. CLI supports `shinku --help`, `shinku run --help`, and `shinku --version` as non-run actions.
12. CLI version output comes from Meson `configuration_data()`.
13. CLI does not reject explicit empty `--config` paths; Config Loader owns path-open failures.
14. CLI does not canonicalize config paths.
15. `shinku run --config` with no path is rejected by argparse and mapped to `UnexpectedArgument`.
16. Duplicate `--config` is rejected by argparse and mapped to `UnexpectedArgument`.

Constraint:

- Documentation and startup errors must be explicit that TOML is the only supported configuration source in this phase. CLI and env hooks must not be accidentally read until support is intentionally introduced.
- Backend selection must stay in TOML and must not be reintroduced through CLI flags in this module.
- CLI syntax diagnostics must not include TOML field-level knowledge.
- `CliCommand` is not a runtime Config and must not duplicate TOML schema fields.
- `main.cc` remains a temporary composition point until Process-control and Backend Interface modules move runtime concerns out of the CLI module.
- Help and version actions exit before Config Loader is called.

### Segment 7: First Config Fields

Decisions:

1. eBPF Backend uses the minimum required config fields: `iface`, `arena_pages`, and `cleanup_interval`.
2. DPDK Backend uses the minimum required config fields: `client_port` and `server_port`.
3. Cache Policy is backend-neutral and belongs in the top-level `cache` section.
4. The first `cache` fields are the minimum set: `max_entries`, `max_response_bytes`, and `cache_negative`.
5. The Config File path has a default value: `./shinku.toml`.
6. Launch command is `shinku run`, with optional override `shinku run --config path/to/file.toml`.
7. The first schema examples include one valid eBPF TOML file and one valid DPDK TOML file using the minimum fields.

Constraint:

- `shinku run` reads `./shinku.toml`.
- `shinku run --config path/to/file.toml` reads the provided TOML file.
- Backend selection stays inside TOML as `backend = "ebpf" | "dpdk"`.

Path rule:

- The default path is exactly `./shinku.toml` relative to the process working directory. The first implementation does not search `/etc`, XDG paths, or env-provided paths.

### Segment 8: TOML Schema and Validation

Decisions:

1. TOML uses the simple table layout: top-level `backend = "ebpf" | "dpdk"`, plus `[ebpf]`, `[dpdk]`, and `[cache]`.
2. `cleanup_interval` is a duration string such as `"10s"` so users can choose the unit.
3. Duration strings support only `ms`, `s`, and `m` in the first implementation.
4. Duration strings get simple validation before backend startup.
5. Unknown TOML keys produce a warning and are then ignored.
6. Config File parsing, validation, and diagnostic output belong to the Config Loader, not `src/cli`.
7. Config failures use a minimum typed enum: `FileNotFound`, `ReadError`, `ParseError`, `SchemaError`, `ValidationError`, and `UnsupportedBackend`.

Constraint:

- Duration validation is intentionally small in the first implementation: accept only explicit supported units (`ms`, `s`, `m`), reject malformed values, reject zero or negative durations, and return a typed Config Validation error before any backend resource is acquired.
- Unknown-key warnings are non-fatal. They must not change the parsed Config and must not silently enable future behavior.
- `src/cli` remains a Config Selector Subcommand. It may pass a path and return an exit code, but it must not contain TOML schema knowledge, field-level validation, or config-specific error formatting.
- Config Loader diagnostics must make misspelled required fields obvious. For example, `leanup_interval = "10s"` should warn about unknown `leanup_interval` and then fail because required `cleanup_interval` is missing.

Example:

```toml
backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 64
cleanup_interval = "10s"

[cache]
max_entries = 65536
max_response_bytes = 4096
cache_negative = true
```

### Segment 9: Config Loader Boundary

Decisions:

1. Config Loader is the owner of Config File reading, TOML parsing, schema validation, duration parsing, warning creation, error creation, and diagnostic output.
2. `src/cli` only selects the Config File path: default `./shinku.toml` or `shinku run --config path/to/file.toml`.
3. Startup proceeds to backend `probe()` only after Config Loader returns a valid `Config`.
4. Config Loader errors use the minimal typed enum `FileNotFound`, `ReadError`, `ParseError`, `SchemaError`, `ValidationError`, and `UnsupportedBackend`.
5. Config Loader owns a small injectable `DiagnosticSink` boundary. The default sink writes to `stderr`; tests can inject a fake sink.

Constraint:

- Config Loader can produce human-readable diagnostics, but backend code should consume typed `Config`, not raw TOML nodes or CLI arguments.
- A warning never changes the effective Config. An error prevents backend construction, `probe()`, and `start()`.
- `src/cli` must not format Config diagnostics itself. It delegates to Config Loader and maps success/failure to process exit.
- Tests should assert Config diagnostics through the fake sink instead of global `stderr` redirection.

### Segment 10: Backend Interface Shape

Decisions:

1. The first C++ `Backend` interface is synchronous: `start()`, `poll()`, and `stop()`.
2. Backend construction receives one `BackendConfig` variant that contains either `EbpfConfig` or `DpdkConfig`.
3. Backends do not own hidden background threads in the first interface. The Host Runtime drives progress by calling `poll()`.
4. `probe()` returns success only when the selected Backend is supported; unsupported capability, permission, wrong-config, and probe execution failures return `BackendError` with human-readable messages.
5. Backend abstraction files live in `src/backend/`.
6. The public `Backend` interface is a pure virtual class. CRTP is not used as the public interface because backend selection is runtime-configured; CRTP may be used later only as a private implementation helper.
7. `BackendRunner` owns lifecycle sequencing for `Created -> Running -> Stopped -> Failed`; backend implementations only perform backend-specific resource actions.
8. `poll()` returns `std::expected<PollStatus, BackendError>`, where `PollStatus` includes `WorkDone` and `NoWork`.
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
27. Backend runner tests cover happy path and lifecycle edges: initial state, automatic probe on start, invalid pre-start poll, `WorkDone`, `NoWork`, poll failure to `Failed`, idempotent stop, stop from `Failed`, destructor best-effort stop, probe error, start failure, and probe while running.

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

### Segment 11: Runtime Loop Ownership

Decisions:

1. The first Host Runtime loop is a simple blocking loop that repeatedly calls `poll()` until shutdown.
2. `poll()` is the canonical backend step name.
3. `poll()` must return quickly. If there is no backend work to process, it returns `NoWork`.
4. Signal handling lives in a separate small process-control module.

Constraint:

- The Host Runtime loop owns backend sequencing: `probe()`, `start()`, repeated `poll()`, then `stop()`.
- The process-control module only turns process signals into shutdown requests. It must not own Config loading, Backend selection, Backend lifecycle, or Backend diagnostics.
- Backend implementations must not hide blocking waits inside `poll()`. Waiting policy, if needed later, belongs to the Host Runtime loop or a later explicit module design.
- `NoWork` is a normal poll result, not an error.

### Segment 12: Process-control Module

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

### Segment 13: Module-by-module Refactor Flow

Decisions:

1. The refactor proceeds by module, not by deciding every future subsystem up front.
2. The active design module is the only module grilled in detail.
3. Future DPDK, DNS cache semantics, and observability redesign decisions are deferred until their modules become active.

Current module:

- eBPF Backend module.

Next module candidate:

- Cache/DNS module.

### Segment 14: eBPF Backend Runtime Boundary

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
24. `make_backend(const Config&)` returns `BackendErrorCode::WrongConfig` if `Config::backend` and `Config::backend_config` disagree.
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
37. `PollStatus` remains `WorkDone` or `NoWork` in Module 7; event counts and backend-specific work categories are deferred.
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

### Segment 15: Runtime Diagnostics/Logging Deferral

Decisions:

1. The current codebase lacks a unified runtime diagnostics/logging boundary.
2. Module 7 does not introduce a process-global singleton logger.
3. Module 7 may emit minimal local warnings for non-fatal eBPF backend conditions, such as log-ring poll errors, while low-level C boundary diagnostics remain temporarily in the C loader.
4. Runtime diagnostics/logging becomes its own module after eBPF and DPDK backend boundaries stabilize and before the full test-suite rewrite.
5. The future diagnostics/logging module should evaluate explicit diagnostics sinks or dependency injection before considering a singleton logger.

Constraint:

- Runtime diagnostics/logging must not become a replacement for typed `std::expected` errors, and it must not reintroduce the deleted Observability Surface unless that future surface is explicitly scoped.

### Segment 16: Module 8A eBPF Resource Ownership

Decisions:

1. Module 8 starts with a hard prerequisite slice, 8A: eBPF Resource Ownership.
2. 8A removes the transitional `EbpfLoaderOps` + `void* context` + central `bpf_ctx` ownership boundary before introducing backend-neutral DNS/cache policy.
3. `EbpfBackend` remains the sole eBPF lifecycle object; a separate `EbpfRuntime` would duplicate the `Backend` contract without an independent consumer or lifetime.
4. `EbpfBackend` owns one `std::unique_ptr<EbpfNativeSession>`. This ownership is indirect but exclusive; no other production object shares or borrows the Session.
5. `ProductionEbpfNativeSession` is a stateful C++ wrapper around the C/libbpf API. One private `NativeResources` aggregate owns the generated skeleton, manual XDP and TCX links, legacy TC state, packet and log rings, and the temporary cache/parser bridge.
6. Native pointers and C structs remain private to `ProductionEbpfNativeSession`; the Session interface does not expose raw pointers, generated skeleton types, opaque resource handles, type-erased handle state, or a resource registry.
7. `EbpfNativeSession` exposes native actions only: capability probes, interface lookup, fixed skeleton preparation, one attach attempt, ring creation and polling, expired-entry cleanup, retry waiting, and aggregate release.
8. `EbpfNativeSession` must not expose `start()`, `stop()`, `run()`, `setup_backend()`, Backend state, retry policy, fallback policy, or cleanup scheduling.
9. `prepare_skeleton()` may combine the fixed native sequence of installing the libbpf print callback, opening the generated skeleton, configuring the arena, disabling auto-attach for manually owned programs, loading, and attaching generated programs. It does not make Backend policy decisions.
10. `EbpfBackend` owns lifecycle orchestration, error context and mapping, XDP retry, TCX-to-legacy fallback, ring polling semantics, packet timeout policy, and cleanup-worker scheduling.
11. The Backend lifecycle remains `probe -> start -> repeated poll -> stop`; `start()` does not enter the long-running poll loop, and no separate `init()` phase is introduced.
12. `BackendRunner` remains the only lifecycle state authority and caller. Backend lifecycle hooks are protected and Runner-owned; tests drive concrete Backends through `BackendRunner`.
13. Start failure leaves cleanup owed. `BackendRunner` invokes `stop()` for partial startup resources, while Session destruction provides a final `noexcept` best-effort release path.
14. The cleanup loop belongs to a private Backend-owned `CleanupWorker` using `std::jthread` and stop-aware C++ wait primitives. It waits one full configured interval before the first cleanup pass and is joined before Session release.
15. `ProductionEbpfNativeSession::release()` owns native dependency order: close packet and log rings, detach manual links, detach legacy TC, destroy only a clsact created by this Session, release the bridge, then destroy the skeleton.
16. Session release attempts every independent native release, returns the first error, and preserves still-owned resources plus their dependencies for a later cleanup attempt when a native operation does not consume them.
17. XDP and TCX auto-attach are disabled before generated skeleton attachment. Manually attached XDP and TCX links are owned only by the Session's dedicated raw-pointer fields and are not written into generated skeleton link fields.
18. Legacy TC tracks whether this Session created clsact. A pre-existing clsact is never destroyed, including when filter attachment fails.
19. The intentional `void*` values are confined to libbpf and legacy C callback trampolines inside the production Session implementation. `bpf_ctx` is not retained as a Host Runtime ownership object.
20. Session methods return `std::expected<T, std::error_code>`. Errno-style failures use `std::generic_category()` only where the wrapped API has an errno-style contract; `EbpfBackend` adds stable Backend error semantics and operation context.
21. Production and tests implement the same private `EbpfNativeSession` interface. `make_backend(const Config&)` injects `ProductionEbpfNativeSession`, while focused tests inject `FakeEbpfNativeSession`.
22. `FakeEbpfNativeSession` uses independent result queues and an explicit call trace. It does not allocate fake native pointers or reproduce production resource-handle state.
23. The old `EbpfPlatform`, per-resource opaque Handle hierarchy, private type-erased Handle implementations, and `dynamic_cast`-based production extraction are removed.
24. 8A preserves the attach sequence: generated skeleton attachment, optional log ring, XDP retry, TCX retry with legacy TC fallback, packet ring creation, then cleanup-worker startup.
25. 8A preserves ring behavior: log-ring `EINTR` returns `NoWork` before packet polling, other log-ring failures are non-fatal warnings, packet-ring `EINTR` returns `NoWork`, and other packet-ring failures return `PollFailed`.
26. The TCX fallback loop remains Backend policy: each unsupported TCX result triggers one legacy TC attempt; after a failed legacy attempt the Backend waits and retries TCX for at most five rounds with the existing backoff.
27. The existing BPF log callback remains in `ProductionEbpfNativeSession`; the general diagnostics/logging boundary remains deferred to Module 10.
28. The optional `ebpf.packet_poll_timeout` is materialized as `100ms` when absent, validated from `1ms` through `1s`, and applies only to packet-ring polling. Log-ring polling keeps a private `100ms` timeout.
29. Module 8B/8C do not depend on `EbpfNativeSession`. Module 8D may request only the narrow native storage binding needed by the cache implementation; cache and DNS policy must not move into the Session.
30. `make_backend(const Config&)` remains the production assembly entry point. A `BackendFactory` type is deferred until multiple construction sources, registry discovery, or injected construction policy create a concrete need.

Constraint:

- This slice must preserve the eBPF Operational Loops: BPF attach/detach, packet ring polling, cleanup scheduling, signal-driven shutdown through `BackendRunner`, and cleanup after partial startup.
- The 8A test boundary should let unit tests cover lifecycle sequencing and error mapping without root, real interfaces, BPF attachment, or specific kernel feature availability.
- See [ADR-0011](../adr/0011-ebpf-runtime-resource-ownership.md).
- See [ADR-0012](../adr/0012-runner-exclusive-backend-lifecycle.md).

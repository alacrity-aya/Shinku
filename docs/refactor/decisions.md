# Confirmed Refactor Decisions

## Starting Point

The refactor starts from `master` on branch `refactor`, not from an empty tree. The existing C code contains behavior that should be treated as regression evidence: DNS parsing, cache admission/eviction, ECS handling, negative caching, BPF arena safety, and tests. Preserve validated product semantics and Operational Loops, not implementation defects discovered while specifying the replacement.

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
- The legacy XDP ECS query parser uses a fixed maximum-address bound before deriving the actual ECS address length, so common IPv4 `/24` queries cannot reach their ECS cache key.
- The legacy userspace ECS response parser rejects `SCOPE PREFIX-LENGTH > SOURCE PREFIX-LENGTH`, although RFC 7871 defines that as valid input requiring special cache treatment.
- The legacy cache key is a 32-bit FNV name hash plus question type and class, and under the MVP Query Profile the type and class are constant, so the effective key is 32 bits. By the birthday bound that is roughly a 3 percent chance of at least one colliding pair at the current 16384-entry map size and roughly 50 percent at the 65536 entries used in the example configuration. A collision does not cause a miss; it makes XDP serve one name's answer for a different name, repeatably for the whole entry lifetime, and downstream caches then propagate it. This is a defect rather than a representation detail.
- `CACHE_VALUE_FLAG_TC_FALLBACK` is written in `src/core/dns_parser.c` and read nowhere; the XDP hit path never inspects `cache_value.flags`. The truncated response is stored under the same Cache Key as the ordinary answer, so a truncated upstream response evicts the good cached answer for that name and every query is served a truncated response for the next five seconds. This is a legacy defect, not behavior to preserve.

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
max_response_bytes = 512
cache_negative = true
max_pending_queries = 8192
pending_query_timeout = "2s"
```

The `[cache]` example is kept current with the Config Schema. `max_response_bytes` was corrected from `4096` (see decision 55), and `max_pending_queries` and `pending_query_timeout` are the required Module 8B additions.

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

### Segment 17: Module 8B Backend-neutral Cache Domain

Decisions:

1. Module 8B defines only the Cache Domain Contract and focused contract tests. It does not cut over the legacy parser/cache path or implement a concrete Cache Store.
2. The existing `[cache]` Config Schema remains the home of Backend-neutral requirements and DNS Policy. Backend-specific cache tuning is not added until a concrete requirement justifies it.
3. `CacheConfig.max_entries` and `CacheConfig.max_response_bytes` are hard requirements. A Backend that cannot satisfy either value fails startup instead of silently reducing it.
4. Negative Cache Admission belongs to DNS Policy. When disabled, a valid NXDOMAIN or NODATA response becomes a Bypass instead of a Cache Candidate.
5. Cache Stores own storage-pressure admission and eviction strategy. The Cache Domain Contract does not require eBPF and DPDK to use the same algorithm.
6. Store Outcomes are `Inserted`, `Updated`, `Replaced`, and `Rejected`. Rejection is an ordinary policy result; operational storage failures use the typed error channel.
7. Capacity, TTL, Fail-open behavior, and storage-safety invariants are preserved. The legacy minimum-TTL, dampening, frequency-sketch, and hot/cold algorithms are not part of the Cache Domain Contract and may be redesigned with the concrete Store.
8. Cache Candidate response bytes are a borrowed view consumed synchronously by Cache Store and are not retained after `store()` returns.
9. The MVP uses synchronous Cache Fill. The contract does not prevent a later asynchronous boundary before DNS Policy, using a bounded memory pool and queue if benchmarks justify it.
10. A future asynchronous fill queue drops new fill work when saturated instead of blocking packet-ring consumption, preserving Fail-open behavior.
11. A Cache Candidate carries TTL. Store and cleanup operations receive monotonic current time explicitly; Module 8B does not introduce an abstract Clock.
12. The backend-neutral Cache Key represents canonical DNS question name, question type, question class, and every semantic admitted by the active Cacheable Query Profile that can change the answer. The current 32-bit FNV hash is a Backend representation, not the domain identity.
13. Cache Store errors use a small stable code set for unavailable storage, write failure, and cleanup failure, with an optional underlying `std::error_code` cause. Backend mechanics do not become public error codes.
14. Expired-entry cleanup belongs to Cache Store, receives monotonic current time, and returns the number of removed entries through a typed result.
15. Canonical DNS question names use a fixed-capacity, allocation-free wire representation with lowercase labels, no compression pointers, a terminating root label, and the DNS 255-byte name limit.
16. Cache Candidate response bytes form a normalized Response Template without Ethernet, IP, or UDP headers. DNS Policy owns parsing, normalization, and the metadata required to bind the template to a later Query; Cache Store treats the bytes as opaque.
17. The Cache Hit Path reduces each response RR's original TTL by time already spent in cache. DNS Policy records TTL field byte offsets while parsing, Cache Candidate borrows that patch plan, and Cache Store persists the offsets plus insertion time so concrete hit paths use a bounded patch loop instead of reparsing DNS.
18. Cache Store is a runtime-polymorphic C++ interface. Its virtual calls occur on Cache Fill and cleanup paths, not on the XDP Cache Hit Path; DNS Policy and composition do not become templates over concrete Store types.
19. A concrete Backend may represent the logical Cache Key with a 128-bit keyed fingerprint for the MVP, accepting negligible probabilistic collision risk instead of performing a full canonical-name comparison on every hit. The eBPF hash algorithm and key provisioning remain 8D decisions.
20. DNS Policy includes every parsed TTL offset in Cache Candidate's borrowed patch plan. A Store that cannot persist the complete plan returns `Rejected`; partial plans are never stored.
21. Cache Hits round remaining TTL down to whole seconds so they never overstate remaining lifetime, including after sub-second cache residence.
22. Cache Entry Kind is a mutually exclusive `Positive`, `NxDomain`, `NoData`, or `TruncatedFallback` value, not Backend flags or Store-side DNS inference.
23. Expired-entry cleanup is bounded and returns `removed_entries` plus `more_work`. The cleanup worker may schedule another stop-aware batch instead of requiring one call to remove every expired entry.
24. Cache Candidate is valid by construction at the DNS Policy boundary. Cache Store does not repeat DNS parsing or policy validation, but it still enforces concrete storage-format and capacity constraints.
25. An individual Cache Fill write failure discards that fill attempt and is reported without making Backend `poll()` fail. This preserves Fail-open behavior for upstream DNS responses that have already completed.
26. An individual cleanup failure is non-fatal and is retried on a later cleanup schedule. Hit-path expiration checks preserve response correctness while reclamation is delayed.
27. Config Loader validates backend-neutral value rules, `probe()` rejects static Backend cache limits that cannot satisfy the Effective Config, and `start()` reports failures that depend on actual resource acquisition.
28. Each concrete Backend owns and composes DNS Policy with its Cache Store. `EbpfNativeSession` remains a native adapter with only the narrow storage binding required by the eBPF Store; DNS Policy and Cache Store are not Host Runtime global services.
29. Cache Store supports concurrent `store()` and `cleanup()` calls and owns the synchronization required by its concrete representation. Backend does not serialize these paths with a shared mutex, and this synchronization does not enter the XDP Cache Hit Path.
30. Cache Store operations are `noexcept` and return expected operational failures through `std::expected`; callers do not add exception-recovery guards around Store calls.
31. `CacheConfig.max_entries` and `CacheConfig.max_response_bytes` are actual runtime limits, not minimum capability requests. Greater physical Backend capacity does not expand the Effective Config.
32. A response whose Cache Hit representation could exceed `CacheConfig.max_response_bytes`, including fields generated or rebound for the current Query, becomes a DNS Policy Bypass and never becomes a Cache Candidate. Responses are never truncated for cache storage or emission.
33. A cleanup result with `more_work` causes the worker to check its stop token and immediately run another bounded batch using a fresh monotonic timestamp. The configured cleanup interval resumes after completion or error.
34. Every concrete Store has one Cache Publication point. `WriteFailed` guarantees that the Candidate never became hit-visible, but does not guarantee rollback of a victim already invalidated before publication. Once publication succeeds, the operation returns a successful Store Outcome; later bookkeeping cannot reclassify that write as failed.
35. `Rejected` leaves all existing Cache Entries hit-visible and does not change cache payload, key ownership, or expiration state. Store may update private admission metadata such as frequency estimates and victim-selection cursors.
36. The eBPF Store uses BPF map update as its Cache Publication point after a complete stable arena write. Its XDP reader validates generation inside the seqlock interval so an old map value cannot accept newly overwritten arena bytes after failed publication.
37. The MVP Cacheable Query Profile accepts only IPv4/UDP standard single-question recursive `A/IN` Queries with `RD=1`, `CD=0`, and `ARCOUNT=0`. A cacheable positive response may contain a CNAME chain ending in an A record; `NXDOMAIN` and `NODATA` for the same Query Profile remain subject to Negative Cache Admission. Queries with any Additional Section, including EDNS, DNSSEC signaling, or ECS, and all other query types and transports are Bypasses. Future profile expansion must add answer-changing semantics to Cache Key identity or normalize them safely before caching.
38. On an eBPF Cache Hit, XDP preserves the current Query Question Section and copies the cached response header and post-question bytes around it. This preserves QNAME case echo without adding a second question-name copy.
39. Cache Candidate preserves the upstream response Transaction ID rather than normalizing it during Cache Fill. Transaction ID is not part of Cache Key identity, and every Cache Hit must replace it with the current Query ID before sending the response.
40. An accepted Candidate whose Cache Key already exists updates that logical entry in its current slot and returns `Updated`; it does not advance replacement selection or evict an unrelated entry.
41. Cache Entry Lifetime is the minimum original TTL across all retained RRs. The whole response expires at that point, while Cache Hit processing still ages every retained RR TTL individually; this is not the legacy minimum-TTL admission threshold.
42. `Rejected` carries no public reason in the MVP. Strategy-specific rejection explanations remain private to concrete Store tests and benchmarks rather than expanding the backend-neutral outcome contract.
43. `Inserted` covers a new key using empty storage or reclaiming an expired entry. `Replaced` is reserved for a new key that displaces a different entry still hit-visible at admission time, so cleanup scheduling does not alter the logical Store Outcome.
44. Cache Store has no independent lifecycle state machine. A concrete Backend creates it from validated limits and acquired native bindings during Backend `start()`, treats creation failure as startup failure, and releases it through RAII before releasing those bindings.
45. Explicit Store and cleanup time uses a strong `CacheTime` value containing nanoseconds in the concrete Backend's Cache Hit clock domain. It does not expose a raw integer, assume a portable `steady_clock` epoch, or require a Clock abstraction.
46. Runtime Store errors remain Fail-open even when repeated indefinitely and never cross a count threshold into `PollFailed`. The cache may converge to misses as entries expire, while upstream forwarding continues.
47. `CacheConfig.max_entries` counts resident logical Cache Entries, not concrete Backend containers. Independently stored answer identities each consume one unit even when a Backend groups several of them under one lookup element; expired entries continue to occupy capacity until reclaimed or replaced.
48. The Cache Domain Contract covers the Cache Fill and cleanup paths only. `CacheStore` has no `lookup()` operation, so no virtual dispatch reaches a Backend's per-packet Cache Hit Path, including the future DPDK userspace hit path that will call its own concrete Store directly.
49. Cache Hit Semantics are still backend-neutral even though they are not expressed as a virtual call. Module 8B specifies expiration, per-RR TTL aging, whole-second rounding, Transaction ID rebinding, and Question Section preservation as rules, and verifies them through shared Cache Hit vectors that every Backend hit path must satisfy whether it is written in BPF C or C++.
50. Module 8B delivers `src/cache/` in namespace `shinku::cache` with the file layout `cache_time.h`, `canonical_name.h`, `cache_key.h`, `cache_candidate.h`, `cache_store.h`, and `cache_store_error.h`, plus the `[cache]` Config Schema additions. It does not define a `CacheEntry` type; the stored form is private to each concrete Store.
51. Module 8B does not define a backend-neutral `PendingQuery` type or correlation interface. The eBPF Backend performs Query Correlation entirely in BPF, so no Host Runtime object consumes it; a userspace correlation type is modeled when the DPDK Backend gives it a real consumer. `max_pending_queries` and `pending_query_timeout` still enter `[cache]` in 8B because Config Schema is a cross-module contract, and they reach the eBPF Pending Query map through 8E.
52. Module 8B does not define the DNS Policy input type for a correlated Response. That boundary type belongs to Module 8C.
53. `max_response_bytes` is validated by Config Loader to the range `[128, 512]`. The upper bound is a backend-neutral DNS protocol rule rather than a Backend capability: the MVP Cacheable Query Profile requires `ARCOUNT = 0`, so no Query advertises an EDNS UDP payload size and RFC 1035 caps the UDP response at 512 bytes. A smaller value is a legitimate storage-density setting because oversized responses Bypass instead of being truncated; below 128 no complete in-profile response can be stored.
54. A Cache Hit emits exactly as many bytes as the stored Response Template, because Cache Key identity fixes the question wire length and a hit only rebinds the current Query's Question Section bytes. One `max_response_bytes` therefore bounds both storage and emission.
55. The example `[cache]` configuration uses `max_response_bytes = 512`. The earlier `4096` example was unsatisfiable: under decisions 3 and 31 it would have made every eBPF startup fail.
56. `TruncatedFallback` is removed. Cache Entry Kind is `Positive`, `NxDomain`, or `NoData`, which is exactly the RFC 2308 trichotomy. A truncated upstream response is a DNS Policy Bypass, and the legacy TC-fallback storage path is deleted with the rest of the legacy path in 8E. This supersedes decision 22 of this segment.
57. Module 8D derives the eBPF arena slot size from `max_response_bytes` instead of keeping the hardcoded `ARENA_ENTRY_SIZE` of 512, so that a smaller configured limit actually buys arena density.
58. Response Template is a verbatim byte copy of the upstream DNS message from the DNS header to the end of the message. DNS Policy does not strip sections, decompress names, or rebuild the message, and the word "normalized" leaves the contract. This makes a Cache Hit byte-identical to the forwarded response except for the Transaction ID and aged TTL fields, and it preserves the current querier's own QNAME case for free, because compression pointers into the Question Section resolve against the rebound question. It is safe because Cache Key identity fixes the question wire length, so every stored offset and compression pointer stays valid. The legacy rebuild path, including `flatten_name` and the thread-local flat buffer, is deleted with the legacy path in 8E. This supersedes decision 16 of this segment.
59. The TTL patch plan covers every RR in the message — Answer, Authority, and Additional — not only the Answer Section. A negative response carries its only TTL in the Authority Section SOA, so an Answer-only plan would replay a fixed TTL and let every Cache Hit re-arm the downstream cache for a full TTL beyond what upstream authorized. This extends decision 17 of this segment.
60. Negative Cache Entry Lifetime is `min(SOA.TTL, SOA MINIMUM)` as defined by RFC 2308 section 5, and a negative response without an SOA in its Authority Section is a Bypass because nothing in it authorizes a cache duration.
61. The legacy five-second negative TTL floor is removed. Raising a one-second authorization to five seconds keeps serving an answer after upstream stopped authorizing it, and it belongs to the same family as the legacy minimum-TTL admission threshold that decision 7 already excluded.
62. The legacy 600-second negative TTL ceiling is removed. It is an undocumented product judgment that conflicts with TTL-only Freshness. If a ceiling is ever needed it becomes an explicit `[cache]` field with its own ADR rather than a constant.
63. Cache Entry Lifetime is the minimum original TTL across every RR in the verbatim message, so the Authority and Additional Sections now participate in it. A response whose Cache Entry Lifetime would be zero is a DNS Policy Bypass: TTL 0 means "do not cache", and admitting it would consume one unit of Cache Capacity with an entry that can never be hit.
64. A Response with `ARCOUNT != 0` is a Bypass, mirroring the Query rule. This also keeps the patch plan safe, because an OPT pseudo-record's TTL field carries an extended RCODE and flags rather than a TTL and can therefore never appear inside a Cache Candidate.
65. `CacheNamespace` is a field of `CacheKey`, not a separate parameter or a per-instance property of a Store. The DNS Service Endpoint changes the answer, so decision 12 already puts it inside key identity; embedding it makes cross-namespace leakage a type error instead of call-site discipline, matches the physical eBPF map key, and makes the decision 19 fingerprint cover the namespace by construction. A Store may still shard its internal representation by namespace.
66. `CacheCandidate` carries `key` by value, `kind`, `lifetime`, a borrowed `response` span, and a borrowed `ttl_offsets` span. It has no separate upstream Transaction ID field: the verbatim template already holds it at offset 0, and a second copy would only create a disagreement to resolve.
67. The patch plan is a borrowed span with no capacity constant in the Cache Domain Contract. Each Store knows `max_response_bytes` at construction and derives its own worst case; a Store that cannot persist the complete plan returns `Rejected` under decision 20.
68. The Response Template stores the complete DNS message including its Question Section rather than a compact header-plus-tail form. Arena slots are fixed size at `max_response_bytes`, so omitting the question buys no density, and keeping the message complete is what the DPDK path and the Cache Hit vectors depend on.
69. `CacheKey` is passed by value inside `CacheCandidate`. The Cache Fill Path runs once per upstream Response rather than once per packet, so the copy is irrelevant next to the lifetime constraints borrowing would add. `CacheEntryKind` is retained even though a verbatim template makes RCODE readable from the bytes, because it is the only DNS meaning a Store gets without parsing and admission strategies have a legitimate reason to treat negative entries differently.
70. `CacheStoreError` is `code + optional std::error_code cause` with no message string, a deliberate divergence from `BackendError`. Store errors live on the Cache Fill Path and decision 46 lets them repeat indefinitely, so a message field would mean a heap allocation per upstream Response inside a `noexcept` path during an error storm. Human-readable text comes from `cache_store_error_name(CacheStoreErrorCode) noexcept`, mirroring `stop_reason_name`.
71. The `cleanup()` batch bound belongs to the Store and is not a parameter. Its unit is representation-specific — a BPF map batch stride is not comparable to a hash bucket walk — so a caller has no basis for choosing it. Callers observe progress only through `more_work`.
72. The Cache Store concurrency contract is exactly one concurrent `store()` caller plus one `cleanup()` that may run concurrently with it. The MVP Cache Fill Path is a single packet-ring consumer, and the deferred asynchronous fill queue is also single-consumer, so requiring writer-writer concurrency would buy nothing and would force every Store to carry a write mutex.
73. `CacheStore` exposes no capacity query. Because `probe()` must reject unsatisfiable cache limits before a Store exists, each Backend has to know its own static capacity ceiling independently of its Store.
74. `CacheTime` is `std::chrono::time_point<CacheClock>`, where `CacheClock` is a tag type that deliberately provides no `now()`. The clock domain differs per Backend — `bpf_ktime_get_ns()` for eBPF, most likely TSC for DPDK — so any shared `now()` would be a convenient, compiling, silently wrong default for one of them. Each Backend constructs `CacheTime` from its own clock source at one visible place, and mixing in a `steady_clock::time_point` stays a compile error.
75. The Cache Time Domain invariant — a Backend passes `store()` and `cleanup()` values from the same clock its Cache Hit Path reads — cannot be enforced across the C++/BPF boundary by types. Modules 8D and 8E owe an integration test that inserts an entry with a short lifetime from userspace and verifies that the XDP hit path flips from hit to miss at the expected boundary.
76. A Cache Hit rewrites only the Transaction ID, the Question Section bytes, and every RR TTL. Every header bit, including `AA`, is replayed verbatim. Conventional caches clear `AA` because they are explicitly addressed resolvers, but Shinku is transparent: the client believes it is talking to the DNS Service Endpoint directly, and that endpoint — CoreDNS with the kubernetes plugin, for example — is genuinely authoritative for the names it answers with `AA=1`. Clearing the bit would let a client detect a Cache Hit and would make the answer look like it passed through an unidentified intermediary. Making this configurable is rejected: it depends on topology rather than preference, and an option would leave both behaviors undertested.
77. `RD` needs no rebinding because the Cacheable Query Profile requires `RD=1`, so a stored response can only ever be hit by a Query whose `RD` already matches. Profile-guaranteed invariants like this are documented in the contract so that implementers do not write runtime handling for cases the profile has already excluded.
78. `max_entries` is an upper bound on resident Cache Entries, where resident means published and not yet removed or replaced, whether or not the entry has expired. It is a resource ceiling, not a promise that this many entries are live at any moment; no cache with deferred reclamation could keep that promise. A Backend must physically provision that many units, which is the decision 3 startup check, and must never exceed it, which is decision 31. This clarifies decisions 3, 31, and 47 rather than changing them.
79. Config Loader validates `max_entries >= 1` and `max_pending_queries >= 1`, leaving physical satisfiability to `probe()` because it depends on Backend settings such as `arena_pages`. `pending_query_timeout` is validated to `[100ms, 10s]`, following the `packet_poll_timeout` precedent of range-checked duration fields. The lower bound blocks the worst kind of misconfiguration, where Pending Queries expire before upstream can answer and the cache silently never fills while reporting no error at all; the upper bound is resource hygiene, since a late Response is still a valid answer bounded by its own TTL.
80. There is no cross-field constraint between `max_pending_queries` and `max_entries`. The two are driven by unrelated quantities — Pending Queries by miss rate times upstream RTT, Cache Entries by working-set size — so a constraint such as `max_pending_queries <= max_entries` would mislead operators in both directions.
81. The physical eBPF key is a plaintext `CacheNamespace` plus a 128-bit keyed fingerprint over the canonical name, question type, and question class. This refines decision 19: cross-namespace isolation becomes exact rather than probabilistic, a fingerprint collision can only confuse two names inside one namespace, and an operator can still read the owning DNS Service Endpoint out of a map dump.
82. The fingerprint must be a keyed PRF with a per-process random secret, such as the SipHash family. Unkeyed 128-bit hashes like xxHash128, FNV-128, or Murmur128 are rejected: without a secret an attacker who can send Queries through the Cache Point can construct a colliding pair offline and turn the cache into a poisoning primitive, which no output width prevents.
83. The fingerprint has exactly one implementation, a shared `static __always_inline` header compiled into both the BPF object and the Host Runtime, following the existing `src/core/hash.h` pattern. The key struct is likewise defined once in the shared `types.h`, with explicit padding, mandatory zero-initialization, and a `static_assert` on its size. Divergent implementations and uninitialized padding produce the same symptom — a permanent zero hit rate with no error anywhere — so one focused test must cover both.
84. The hash secret is written into `.rodata` between skeleton open and load, so Module 8D extends `prepare_skeleton()` with that input. This is the one place where 8D changes the 8A Session signature. BPF maps are not pinned today; introducing pinning later would require revisiting secret lifetime, because entries fingerprinted under a previous secret become unreachable while still occupying capacity.
85. Module 8D verifies BPF verifier complexity for the fingerprint and the TTL patch loop at the start of the slice rather than at the end. If the combination does not fit, the documented fallback is using the complete logical key as the BPF map key, which removes collision risk entirely at the cost of stack space and per-packet hashing.
86. Module 8B delivers three test artifacts rather than value-type tests alone: focused value-type tests, a reusable Cache Store conformance suite, and language-neutral Cache Hit vectors. A contract that exists only in prose is not a contract.
87. The conformance suite asserts only contract-observable behavior and never a strategy, because decision 5 keeps admission and eviction algorithms private to each Store. `FakeCacheStore` exists to prove the suite is executable, not to serve as a reference implementation, and every concrete Store including the eBPF and future DPDK Stores runs the same suite.
88. Cache Hit vectors are language-neutral data files under `tests/vectors/cache_hit/`, consumed by a C++ reference applier in 8B and by the XDP integration test in 8D. They must be written in 8B: deferred to 8D they would be derived from the XDP implementation instead of constraining it, which would empty out decision 49. Coverage includes sub-second residence rounding, multi-section TTL aging with an Authority SOA, case-different question echo, Transaction ID rebinding, and the hit and miss sides of the expiry boundary.

Constraint:

- Module 8B must not depend on `EbpfNativeSession`, libbpf, BPF map or arena types, DPDK types, or packet-buffer ownership types.

### Segment 18: Module 8 MVP ECS Scope

Decisions:

1. The target MVP is a Transparent Cache at either a node-local or DNS-service-local Cache Point in front of CoreDNS, Unbound, or another existing DNS service. Kubernetes is one deployment example rather than a product boundary; a supported Cache Point must let the same Shinku instance observe the Query and corresponding Response and return a Cache Hit correctly.
2. The project has no demonstrated ECS traffic or geo-sensitive production requirement in the current phase. ECS-aware Caching is deferred until a concrete deployment and benchmark show that ECS-bearing traffic needs cache acceleration.
3. ECS Pass-through is sufficient for the MVP. An ECS-bearing Query is never answered from a non-ECS Cache Entry, and its Response never becomes a Cache Candidate; both continue through the existing DNS path under Fail-open behavior.
4. Ignoring ECS while performing an ordinary Cache Key lookup is not an MVP fallback because it can serve a network-tailored answer outside its valid client network.
5. Deferring ECS-aware Caching does not require removing the existing compile-time feature gate during the refactor, but the replacement 8B-8E path does not treat the legacy ECS implementation as a required compatibility surface.
6. The primary MVP performance claim is higher single-node throughput, lower p99 latency, and lower DNS-service CPU use for hot `A/IN` Queries. Benchmarks, rather than architecture alone, determine whether a deployment benefits.
7. Internal and public DNS names share the same Cache Domain Contract. The MVP does not classify names by suffix or depend on Kubernetes APIs; eligibility and freshness come from DNS semantics and the active Cacheable Query Profile.
8. Performance evaluation compares at least a reference DNS service without its native cache, the service with its native cache, the service with Shinku, and the service with both caches enabled. This separates XDP offload benefit from the benefit of merely adding any cache.
9. Cache state is local to one Shinku instance and one Cache Point. Instances warm independently and do not share, replicate, or coordinate Cache Entries in the MVP.
10. Cache Entries are isolated by the original DNS Service Endpoint. A Query for the same DNS question against a different destination endpoint belongs to a different Cache Namespace, while multiple backend instances represented by the same service endpoint may share that namespace.
11. The MVP uses TTL-only Freshness for internal and public names. It does not watch Kubernetes APIs, consume active invalidation events, or add DNS-service-specific purge integration.
12. The MVP acceleration target is IPv4/UDP single-question `A/IN`, including a CNAME chain ending in A and configured negative admission for the same Query Profile. `AAAA`, `SRV`, `TXT`, `MX`, `PTR`, DNSSEC/`DO=1`, ECS, unsupported EDNS semantics, multi-question messages, and TCP are Bypasses.
13. The MVP does not parse EDNS options on the Cache Hit Path. Any Query with `ARCOUNT != 0` is a Bypass, which safely includes ECS and DNSSEC-bearing Queries at the cost of bypassing otherwise harmless EDNS forms until traffic measurements justify a broader classifier.
14. The MVP derives Cache Namespace from the original Query destination IPv4 address and UDP port observed at the Cache Point. It does not depend on Kubernetes Service or Pod identity, DNS suffixes, or a global cluster identifier.
15. The performance claim is falsifiable: under the same correctness rules, workload, and hardware, Shinku combined with a DNS service's native cache must show a repeatable improvement in throughput, p99 latency, or DNS-service CPU use over that native cache alone. If none improves, the project does not claim deployment value from XDP caching for that workload.
16. The MVP requires Query Correlation before Cache Fill. Only an eligible Cache Miss creates a Pending Query; a Bypass Query creates none, so its Response cannot be laundered into a Cache Candidate even when that Response looks like an ordinary `A/IN` answer.
17. Response network metadata may identify a candidate DNS Service Endpoint, but the final Cache Namespace and cache eligibility come from a matching live Pending Query. A standalone, expired, or mismatched Response continues through the normal network path and never becomes a Cache Candidate.
18. Pending Query creation and correlation are Fail-open and affect cache admission only. Capacity exhaustion or an operational failure skips Cache Fill for that exchange without blocking the Query or Response, failing Backend polling, or invalidating existing Cache Entries.
19. Query Correlation establishes exchange consistency rather than DNS answer authenticity. It does not replace DNSSEC or turn a trusted DNS Service Endpoint into a cryptographically authenticated source.
20. An MVP Cache Point must observe tuple-symmetric IPv4/UDP exchanges: the Response source/destination endpoints reverse the Query destination/source endpoints. If NAT or transparent proxying between observation points breaks that identity, Query Correlation fails closed for Cache Fill while packet forwarding remains Fail-open; the MVP does not integrate conntrack or infer a weaker identity.
21. Module 8 extends `[cache]` with required `max_pending_queries` and `pending_query_timeout` fields. They have no implicit defaults: the former configures Pending Query Capacity and the latter is a positive duration string using the existing Config Schema duration syntax.
22. Pending Query Capacity is independent of `CacheConfig.max_entries`. Pending Queries are transient correlation state, do not consume Cache Capacity, and cannot displace or invalidate Cache Entries.
23. Query Correlation consumes a Pending Query only after the live record matches the reversed network endpoints, DNS Transaction ID, and Question identity. A Question mismatch suppresses Cache Fill but leaves the Pending Query available for a later matching Response or expiration; the first complete match consumes it, so duplicate Responses cannot perform another Cache Fill.
24. The eBPF physical Pending Query representation remains undecided between `BPF_MAP_TYPE_LRU_HASH` and a bounded `BPF_MAP_TYPE_HASH` with explicit batch cleanup. Module 8D must benchmark both under identical capacity, timeout, steady-miss, burst-over-capacity, delayed-response, and lost-response workloads before choosing. The comparison includes throughput, p99 latency, CPU cost including cleanup, correlation success rate, and pressure-induced skips or evictions.
25. For the eBPF Backend, TC validates the Response Question identity before consuming Pending Query state or publishing a packet-ring event for Cache Fill. A mismatched Response remains on the normal network path without deleting the live Pending Query; a complete match is deleted before its Response is offered to the Host Runtime.
26. `pending_query_timeout` is an inactivity timeout measured from the most recently observed Query with the same correlation identity, not an absolute lifetime from the first Query. An identical retransmission refreshes `last_seen`; a complete Response match still consumes the record, and the MVP adds no separate absolute Pending Query lifetime.

Constraint:

- Module 8 must leave a clear future extension point for ECS-aware Caching without adding ECS coverage, correlation, variant storage, or response-synthesis complexity to the MVP Cache Domain Contract.

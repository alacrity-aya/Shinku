# Shinku Refactor Plan

Status: canonical execution plan for the C++/DPDK refactor. Future refactor work must use this file as the module sequence and decision reference.

## How to Use This Plan

- Refactor one module at a time.
- Do not make implementation decisions for later modules until that module becomes active.
- Before editing code, read the active module section and the relevant confirmed decisions below.
- After each module, run its verification commands and update the module status in this file.
- Keep the eBPF Backend runnable unless the selected host is explicitly unsupported, such as missing usable BPF arena support.

## Module Sequence

| Order | Module | Status | Purpose |
|---:|---|---|---|
| 1 | Build/Test Baseline | complete | Establish the current build and test state before behavior changes. |
| 2 | Observability Removal | pending | Delete current observability/degraded/event-bus surface while preserving operational loops. |
| 3 | Config Module | complete | Add C++23 TOML Config Loader, validation, typed errors, and diagnostics. |
| 4 | CLI Module | complete | Reduce CLI to `shinku run [--config path]` config-file selection. |
| 5 | Process-control Module | pending | Move signal handling and shutdown request propagation out of CLI/backend code. |
| 6 | Backend Interface Module | pending | Introduce C++ Backend lifecycle interface and shared status/result types. |
| 7 | eBPF Backend Module | pending | Adapt existing eBPF loader behind the Backend interface and keep it runnable. |
| 8 | Cache/DNS Module | pending | Separate backend-neutral DNS/cache policy from eBPF storage details. |
| 9 | DPDK Backend Module | pending | Implement the DPDK backend after common interfaces are stable. |
| 10 | Test Suite Rewrite | pending | Rewrite unreliable legacy tests into module-focused regression tests as refactored modules stabilize. |

Current active module:

- Module 5: Process-control Module.

## Test Policy During Refactor

- The legacy test suite is not a reliable quality gate. It has environment-sensitive sanitizer failures and uneven coverage.
- Existing test results are recorded as baseline signals, not as proof of product correctness.
- Do not spend effort preserving tests for modules that are intentionally deleted, such as current observability, degraded mode, and event bus tests.
- Each rewritten module should gain focused tests for its new contract.
- The broader legacy test suite is rewritten as a dedicated module after the runtime boundaries stabilize.
- Do not migrate the whole legacy suite to a C++ framework as part of CLI/Config. New C++ module tests use Catch2 because the current tests are executable-focused, module-local, and do not need mocks or fixtures heavy enough to justify GTest.

## Module Plans

### Module 1: Build/Test Baseline

Goal:

- Record the current build and test behavior before refactoring.

Scope:

- Meson setup/build/test only.
- No source-code behavior changes.

Steps:

1. Run `meson setup build` if no build directory exists.
2. Run `meson compile -C build`.
3. Run `meson test -C build`.
4. Record any existing failures in this file before starting Module 2.

Verification:

- `meson compile -C build`
- `meson test -C build`

Rollback:

- No code rollback should be needed. If generated build files are bad, recreate the build directory.

Baseline result:

- `meson compile -C build` passes on 2026-07-19.
- `meson test -C build` fails 10/10 under the current managed environment because LeakSanitizer aborts under ptrace.
- Re-running with leak detection disabled shows 6/10 passing and 4/10 failing: `Observability HTTP Test`, `Arena List Test`, `Arena Hash Table Test`, and `Cache Store Correctness Test`.
- These failures are treated as pre-existing baseline issues. The refactor will not rely on the legacy suite as the only quality gate.

### Module 2: Observability Removal

Goal:

- Remove the current Observability Surface completely without deleting backend-critical Operational Loops.

Scope:

- Remove degraded mode, runtime event bus, health/readiness HTTP endpoints, Prometheus metrics, BPF counters, dashboards/options, and observability tests.
- Preserve BPF attach/detach, ring polling, cleanup scheduling, and signal-driven shutdown.

Likely files:

- `meson.build`
- `meson.options`
- `tests/unit/meson.build`
- `src/core/obs_http.c`
- `src/core/obs_http.h`
- `src/core/obs_metrics.c`
- `src/include/obs_metrics.h`
- `src/include/obs_bpf_metrics.h`
- `src/core/degraded_mode.c`
- `src/include/degraded_mode.h`
- `src/runtime/events.c`
- `src/runtime/events.h`
- `tests/unit/obs/`
- `tests/unit/degraded/`
- `tests/unit/runtime/`
- observability references in `src/core/loader.c`, `src/core/dns_parser.c`, `src/core/cache_ops.c`, and `src/core/cache_types.h`

Verification:

- `meson compile -C build`
- `meson test -C build`

Rollback:

- Revert only Module 2 edits and keep Module 1 notes.

### Module 3: Config Module

Goal:

- Introduce the C++23 Config domain model and TOML Config Loader.

Scope:

- Create an independent `src/config/` module. Config parsing must not live under `src/cli/`.
- Add C++ build support.
- Use `toml++`.
- Support default path `./shinku.toml`.
- Do not provide TOML field defaults in the MVP.
- Validate `backend`, selected backend section, backend-neutral `[cache]`, and duration strings.
- Unknown keys warn and are ignored.
- Config Loader owns diagnostics through injectable `DiagnosticSink`.
- Produce a validated C++ `Config`; do not expose raw TOML nodes to CLI or backend code.

File layout:

- `src/config/config.h`: `Config`, `EbpfConfig`, `DpdkConfig`, `CacheConfig`, and backend selector types. This is the parsed runtime configuration model and must not depend on TOML or CLI.
- `src/config/config_error.h`: `ConfigErrorCode`, `ConfigError`, and `ConfigWarning` typed status structures. `ConfigError` includes the Config File path when available. This does not print diagnostics.
- `src/config/diagnostic_sink.h`: `DiagnosticSink` interface plus `StderrDiagnosticSink` default implementation. Tests can inject a fake sink.
- `src/config/toml_loader.h`: public Config Loader entrypoint, such as `load_config(path, sink)`.
- `src/config/toml_loader.cc`: TOML file reading, `toml++` parsing, schema validation, duration parsing, unknown-key warnings, and error creation.
- `src/config/legacy_env_adapter.h`: temporary adapter from C++ `Config` to old `struct env`.
- `src/config/legacy_env_adapter.cc`: temporary adapter implementation used only until the eBPF Backend Module replaces the old loader entrypoint.
- `tests/unit/config/config_loader_test.cc`: Config Loader unit tests.

Public API:

```cpp
std::expected<Config, ConfigError>
load_config(const std::filesystem::path& path, DiagnosticSink& sink);
```

API contract:

- On success, return a complete validated `Config`.
- On warning, write through `DiagnosticSink` and continue if the effective Config remains valid.
- On error, write through `DiagnosticSink` and return `ConfigError`.
- `load_config()` is the only TOML-aware public API in the first Config Module.
- `load_config()` does not call `std::filesystem::exists()` before opening. It opens the path directly and maps open/read failures to `FileNotFound` or `ReadError`.
- After TOML parse succeeds, Config Loader runs an unknown-key warning pass before hard validation.
- If TOML parse fails, there is no AST to scan, so Config Loader emits only the parse error.
- During hard validation, Config Loader returns on the first hard error. It does not collect all validation errors in the MVP.
- Config diagnostics for schema and validation issues must include the TOML field path, such as `ebpf.cleanup_interval`.

Config error API:

```cpp
enum class ConfigErrorCode {
    FileNotFound,
    ReadError,
    ParseError,
    SchemaError,
    ValidationError,
    UnsupportedBackend,
};

struct ConfigError {
    ConfigErrorCode code;
    std::filesystem::path path;
    std::string message;
};
```

Temporary legacy adapter:

```cpp
std::expected<env, ConfigError>
to_legacy_env(const Config& config);
```

Adapter contract:

- Support only `backend = "ebpf"` while the old eBPF loader still takes `struct env`.
- Return `UnsupportedBackend` for `backend = "dpdk"` until the DPDK Backend Module exists.
- Fill only fields required by the current eBPF loader path.
- Delete this adapter after the eBPF Backend Module owns eBPF lifecycle through the C++ Backend interface.

Minimum TOML examples:

```toml
backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 1024
cleanup_interval = "10s"

[cache]
max_entries = 65536
max_response_bytes = 4096
cache_negative = true
```

```toml
backend = "dpdk"

[dpdk]
client_port = 0
server_port = 1

[cache]
max_entries = 65536
max_response_bytes = 4096
cache_negative = true
```

Schema note:

- Both examples are valid Config Module inputs.
- During the legacy adapter phase, only the eBPF example can continue into the old loader path. The DPDK example parses as Config but returns `UnsupportedBackend` when converted through `to_legacy_env()`.
- The only default in this phase is the Config File path `./shinku.toml`, selected by the CLI Module.
- TOML fields have no defaults in the MVP. Required fields must be written explicitly.
- Unselected backend tables are allowed to exist and are not required to be complete.
- Unknown keys inside any known table, including an unselected backend table, produce warnings and are ignored.
- Unselected backend tables must not change the effective Config for the selected backend.
- The final `Config` retains only the selected backend's parsed config plus backend-neutral `CacheConfig`; it does not retain parsed config from unselected backend tables.

Minimum hard validation:

- `backend` must be exactly `"ebpf"` or `"dpdk"`.
- Missing required TOML fields are errors; Config Loader must not synthesize field defaults.
- Hard validation stops at the first error.
- The selected backend's table must exist and contain its required fields.
- The unselected backend's table may be missing or incomplete.
- The unselected backend's table is never required to become a valid `EbpfConfig` or `DpdkConfig`.
- `[cache]` must exist and contain its required fields.
- `ebpf.arena_pages` must be at least `1024`.
- `ebpf.cleanup_interval` must be greater than zero and use only `ms`, `s`, or `m`.
- `dpdk.client_port` and `dpdk.server_port` must be in `0..65535` and must not be equal.
- `cache.max_entries` must be greater than zero.
- `cache.max_response_bytes` must be greater than zero.
- `cache.cache_negative` must be a boolean.
- Unknown keys produce warnings and are ignored; they are not hard validation failures.

Diagnostic format examples:

- `warning: unknown key dpdk.foo`
- `error: missing required key ebpf.cleanup_interval`
- `error: invalid duration ebpf.cleanup_interval: expected positive duration with unit ms, s, or m`

Verification:

- Config unit tests for valid eBPF config, valid DPDK config, missing required fields, no field-default synthesis, bad duration, diagnostic field paths, direct-open file failure mapping, `ConfigError` path retention, unknown-key warning before missing-field error, first-hard-error behavior, unselected incomplete backend table, unsupported backend through the legacy adapter, and legacy eBPF adapter mapping.
- Config unit tests must assert that unselected backend config is not retained in the returned `Config`.
- `meson compile -C build`
- `meson test -C build`

Implementation result:

- Added C++23 `src/config/` with typed `Config`, selected-backend-only `BackendConfig`, typed `ConfigError`, injectable diagnostics, TOML loader, and temporary `to_legacy_env()` adapter.
- Added `tomlplusplus` Meson fallback wrap.
- Added `tests/unit/config/config_loader_test.cc` using Catch2 through `catch2-with-main`.
- Focused verification passes with LeakSanitizer disabled in this managed environment: `ASAN_OPTIONS=detect_leaks=0 build/tests/unit/config_loader_test`.

### Module 4: CLI Module

Goal:

- Make CLI a thin Config Selector Subcommand.

Scope:

- Support `shinku run`.
- Support `shinku run --config path/to/file.toml`.
- Support `shinku --help` and `shinku run --help`; both print usage and exit successfully.
- Support `shinku --version`; it prints the Meson project version and exits successfully.
- Reject all other CLI forms in the MVP, including `shinku --config path`, `shinku run -c path`, and `shinku run --backend ebpf`.
- Reject `-h`, `shinku run --version`, duplicate `--config`, missing `--config` values, and all short aliases in the MVP.
- Do not support env vars.
- Do not preserve old CLI flag compatibility.
- CLI must not understand TOML schema or format Config diagnostics.
- CLI owns only CLI syntax diagnostics, such as missing subcommand or unsupported CLI option.
- CLI parsing returns a typed command object instead of scattering argument checks through `main()`.
- CLI parsing uses `argparse` through a Meson wrap, while `parse_cli()` keeps the project's typed `std::expected<CliResult, CliError>` boundary.
- Old `src/cli/config.c` and `src/cli/config.h` are deleted or renamed during this module; they must not remain as the canonical Config authority.

File layout:

- `src/cli/cli.h`: `CliCommand`, `CliError`, and `parse_cli()` declarations.
- `src/cli/cli.cc`: strict `argparse`-backed parser for `shinku run [--config path]`.
- `src/cli/main.cc`: temporary process entrypoint wiring `parse_cli()`, `load_config()`, `to_legacy_env()`, and the old eBPF loader path until later modules move runtime concerns out.
- generated config/version header from Meson `configuration_data()`: provides the version string used by `shinku --version`.

Accepted forms:

```bash
shinku run
shinku run --config ./custom.toml
shinku --help
shinku run --help
shinku --version
```

Rejected forms:

```bash
shinku --config ./custom.toml
shinku run -c ./custom.toml
shinku run --backend ebpf
shinku -h
shinku run --version
shinku run --config
shinku run --config a.toml --config b.toml
```

Diagnostic boundary:

- CLI syntax errors are printed by CLI.
- Config File read/parse/schema/validation diagnostics are printed by Config Loader.
- CLI syntax errors must not mention TOML schema fields.

CLI diagnostic examples:

- `error: expected subcommand: run`
- `error: Unknown argument: -c`
- `error: usage: shinku run [--config path]`

CLI parser API:

```cpp
enum class CliErrorCode {
    MissingSubcommand,
    UnsupportedSubcommand,
    MissingConfigPath,
    UnsupportedOption,
    UnexpectedArgument,
};

struct CliError {
    CliErrorCode code;
    std::string message;
};

struct CliCommand {
    std::filesystem::path config_path;
};

enum class CliAction {
    Run,
    ShowHelp,
    ShowVersion,
};

struct CliResult {
    CliAction action;
    std::optional<CliCommand> command;
};

std::expected<CliResult, CliError> parse_cli(int argc, char** argv);
```

API contract:

- `parse_cli()` only parses CLI syntax.
- `parse_cli()` does not open, parse, or validate the Config File.
- `CliCommand::config_path` defaults to `./shinku.toml` for `shinku run`.
- CLI does not canonicalize `CliCommand::config_path`; Config Loader is responsible for opening the path as provided.
- CLI does not validate whether a provided config path is empty or openable; Config Loader owns those diagnostics.
- `shinku run --config` with no following path is rejected by argparse and mapped to `UnexpectedArgument`.
- Duplicate `--config` is rejected by argparse and mapped to `UnexpectedArgument`.
- `ShowHelp` and `ShowVersion` actions must not call Config Loader.
- Version output is sourced from Meson `configuration_data()`, not duplicated as a hardcoded CLI string.
- `CliError` represents CLI syntax errors only and must not mention TOML schema fields.
- CLI MVP does not include a complex help system; syntax failures print an error plus usage.
- `main.cc` may call Config Loader and the temporary legacy adapter, but CLI parser code must not.

Verification:

- CLI smoke test for default path, explicit `--config`, empty config path delegation, rejected unsupported forms, missing config path, duplicate `--config`, help/version actions, CLI syntax diagnostics, typed `CliResult` results, and `CliErrorCode` coverage.
- `meson test -C build`

Implementation result:

- Replaced old `src/cli/config.c`, `src/cli/config.h`, and `src/cli/main.c` with `src/cli/cli.h`, `src/cli/cli.cc`, and `src/cli/main.cc`.
- CLI now owns only syntax parsing and version/help output. Config file diagnostics remain in `src/config/`.
- Added Meson-generated `version.h` via `configuration_data()`.
- Added `argparse` Meson wrap for CLI parsing.
- Removed project-local preflight parsing and manual argparse failure classification; argparse now owns CLI argument validation in the MVP, with parse failures mapped to typed `CliError`.
- Added temporary `src/runtime/legacy_env.h` and `src/runtime/legacy_ebpf_runner.c` C ABI bridge to keep the existing eBPF runtime runnable until Backend Interface/eBPF Backend modules replace it.
- CLI parser tests use Catch2 through `catch2-with-main`.
- Focused verification passes with LeakSanitizer disabled in this managed environment: `ASAN_OPTIONS=detect_leaks=0 build/tests/unit/cli_parser_test`.

### Module 5: Process-control Module

Goal:

- Isolate process signal handling from CLI and Backend code.

Scope:

- Convert `SIGINT`/`SIGTERM` into shutdown requests.
- Do not own Config loading, Backend selection, Backend lifecycle, or diagnostics.

Verification:

- Unit test or small smoke test for shutdown request state.
- `meson test -C build`

### Module 6: Backend Interface Module

Goal:

- Define the C++ Backend lifecycle contract.

Scope:

- Interface uses `probe()`, `start()`, `poll_once()`, and `stop()`.
- `probe()` is pure, side-effect-free, and returns typed status plus explanation messages.
- `poll_once()` must return quickly. If no work exists, return `NoWork`.
- Construction receives a `BackendConfig` variant.

Verification:

- Fake backend tests for lifecycle sequencing and `NoWork`.
- `meson test -C build`

### Module 7: eBPF Backend Module

Goal:

- Wrap existing eBPF behavior behind the Backend interface.

Scope:

- Preserve BPF build, skeleton generation, attach/detach, ring polling, cache cleanup, and existing behavior tests.
- If BPF arena is unavailable, selected eBPF backend fails as unsupported. Do not introduce compatible-store fallback.

Verification:

- eBPF build succeeds.
- Existing parser/cache/eBPF-relevant tests pass where host capabilities allow.

### Module 8: Cache/DNS Module

Goal:

- Separate backend-neutral DNS/cache policy from eBPF-specific storage details.

Scope:

- Preserve DNS parsing, ECS behavior, cache admission/eviction, negative caching, TTL behavior, and arena safety semantics.
- Do not design DPDK-specific behavior here beyond what the backend-neutral interface requires.

Verification:

- DNS parser tests.
- Cache store tests.
- DNS hash tests.

### Module 9: DPDK Backend Module

Goal:

- Add the DPDK Backend after common runtime, config, and cache interfaces are stable.

Scope:

- Implement minimum configured `client_port` and `server_port` behavior first.
- Keep eBPF backend runnable.
- Do not reintroduce observability unless explicitly scoped later.

Verification:

- DPDK build path.
- DPDK-specific smoke tests where available.
- Existing eBPF/cache/parser tests still pass.

## Confirmed Decisions

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

## Current Code Facts

- `src/core/loader.c` currently owns BPF lifecycle, ring polling, cleanup thread lifecycle, degraded mode, and observability startup.
- `src/core/dns_parser.c` performs response validation and cache insertion, but it directly counts observability metrics.
- `src/core/cache_types.h` carries `struct obs_metrics*` inside cache context.
- `src/bpf/cache.bpf.c` contains BPF-side observability counters and sampling configuration.
- `meson.build` and `meson.options` expose observability build flags.
- Tests include behavior tests that should be preserved, and observability-specific tests that may be deleted or parked.

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
10. Reintroduce a cleaner Observability Surface later only if explicitly scoped.

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
2. `probe()` is a pure capability check with no side effects. It answers whether the selected Backend is supported on the current host with the validated Config.
3. Backend selection is fixed at startup for the whole process lifetime. Runtime backend switching is out of scope.

Constraint:

- `probe()` can inspect system capabilities and configuration validity, but it must not reserve hugepages, bind NIC ports, create BPF maps, open BPF skeletons, spawn threads, attach programs, or mutate process/global state.
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

1. The first C++ `Backend` interface is synchronous: `start()`, `poll_once()`, and `stop()`.
2. Backend construction receives one `BackendConfig` variant that contains either `EbpfConfig` or `DpdkConfig`.
3. Backends do not own hidden background threads in the first interface. The Host Runtime drives progress by calling `poll_once()`.
4. `probe()` returns typed capability status plus human-readable explanation messages for unsupported features.

Constraint:

- A synchronous `poll_once()` keeps lifecycle ownership visible while the eBPF backend is being adapted and the DPDK backend is still new.
- `BackendConfig` variant is selected from the validated top-level `Config`; backend implementations must reject the wrong variant as a typed programmer/configuration error instead of reading raw TOML.

Probe role:

- `probe()` is the pre-start capability gate. It is not a warm-up, not partial startup, and not a fallback mechanism.
- eBPF examples: verify required kernel capabilities, usable BPF arena support, interface existence, and permissions that can be checked without attaching programs or creating maps.
- DPDK examples: verify DPDK support is compiled/available and configured port identifiers look usable without binding ports or reserving runtime resources.
- Probe results must be machine-readable and operator-readable. Example: `UnsupportedBackend` plus `eBPF backend requires BPF arena support, but the target kernel does not provide it`.

### Segment 11: Runtime Loop Ownership

Decisions:

1. The first Host Runtime loop is a simple blocking loop that repeatedly calls `poll_once()` until shutdown.
2. `poll_once()` is the canonical backend step name.
3. `poll_once()` must return quickly. If there is no backend work to process, it returns `NoWork`.
4. Signal handling lives in a separate small process-control module.

Constraint:

- The Host Runtime loop owns backend sequencing: `probe()`, `start()`, repeated `poll_once()`, then `stop()`.
- The process-control module only turns process signals into shutdown requests. It must not own Config loading, Backend selection, Backend lifecycle, or Backend diagnostics.
- Backend implementations must not hide blocking waits inside `poll_once()`. Waiting policy, if needed later, belongs to the Host Runtime loop or a later explicit module design.
- `NoWork` is a normal poll result, not an error.

### Segment 12: Module-by-module Refactor Flow

Decisions:

1. The refactor proceeds by module, not by deciding every future subsystem up front.
2. The active design module is the only module grilled in detail.
3. Future DPDK, DNS cache semantics, and observability redesign decisions are deferred until their modules become active.

Current module:

- Backend lifecycle and Host Runtime loop.

Next module candidate:

- Process-control module, limited to signal handling and shutdown request propagation.

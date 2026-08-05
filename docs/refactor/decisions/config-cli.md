# Config and CLI Decisions

## Segment 5: Config Model for `src/cli`

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

## Segment 6: Config Source Compatibility

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

## Segment 7: First Config Fields

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

## Segment 8: TOML Schema and Validation

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

## Segment 9: Config Loader Boundary

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

# Module 3: Config Module

Goal:

- Introduce the C++23 Config domain model and TOML Config Loader.

Current contract amendment: Module 9 keeps `backend = "dpdk"` only as a Backend selector. DPDK EAL/device configuration
is supplied after the CLI `--` separator, so the current Config model has no `DpdkConfig` fields. Obsolete `[dpdk]`
tables are temporarily ignored pending an explicit migration decision; the legacy adapter described here was deleted
during Module 8.

Scope:

- Create an independent `src/config/` module. Config parsing must not live under `src/cli/`.
- Add C++ build support.
- Use `toml++`.
- Support default path `./shinku.toml`.
- Do not provide TOML field defaults in the MVP, except for the later-added optional `ebpf.packet_poll_timeout`, which defaults to `100ms` to preserve existing eBPF configurations.
- Validate `backend`, the selected eBPF section, backend-neutral `[cache]`, and duration strings.
- Unknown keys warn and are ignored.
- Config Loader owns diagnostics through injectable `DiagnosticSink`.
- Produce a validated C++ `Config`; `CacheConfig` and `EbpfConfig` are validated value objects whose factories own
  their numeric and duration invariants. Do not expose raw TOML nodes to CLI or backend code.

File layout:

- `src/config/config.h`: `Config`, `EbpfConfig`, `DpdkBackendSelection`, `CacheConfig`, and backend selector types. This is the parsed runtime configuration model and must not depend on TOML or CLI.
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
- Config Loader owns TOML schema, text parsing, and diagnostics. It delegates parsed `CacheConfig` and `EbpfConfig`
  values to their factories and maps typed validation failures back to field-specific diagnostics.
- Config diagnostics for schema and validation issues must include the TOML field path, such as `ebpf.cleanup_interval`.
- The eBPF `packet_poll_timeout` field is optional; when absent, Config Loader materializes `100ms`.

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

Historical temporary legacy adapter (deleted during Module 8):

```cpp
std::expected<env, ConfigError>
to_legacy_env(const Config& config);
```

Historical adapter contract:

- Support only `backend = "ebpf"` while the old eBPF loader still takes `struct env`.
- Returned `UnsupportedBackend` for `backend = "dpdk"` before the DPDK Backend Module existed.
- Fill only fields required by the current eBPF loader path.
- Delete this adapter after the eBPF Backend Module owns eBPF lifecycle through the C++ Backend interface.

Minimum TOML examples:

```toml
backend = "ebpf"

[ebpf]
iface = "eth0"
arena_pages = 1024
cleanup_interval = "10s"
packet_poll_timeout = "100ms"

[cache]
max_entries = 65536
max_response_bytes = 512
cache_negative = true
max_pending_queries = 8192
pending_query_timeout = "2s"
```

```toml
backend = "dpdk"

[cache]
max_entries = 65536
max_response_bytes = 512
cache_negative = true
max_pending_queries = 8192
pending_query_timeout = "2s"
```

Schema note:

- Both examples are valid current Config inputs and can be constructed through the Backend factory. The DPDK example
  requires launch-time EAL arguments only when DPDK defaults do not already expose exactly two ports.
- The historical legacy adapter accepted only eBPF and no longer exists.
- The only default in this phase is the Config File path `./shinku.toml`, selected by the CLI Module.
- TOML fields have no defaults in the MVP except optional `ebpf.packet_poll_timeout`, which defaults to `100ms`; all other required fields must be written explicitly.
- Unselected backend tables are allowed to exist and are not required to be complete.
- Unknown keys inside supported tables produce warnings and are ignored. Obsolete `[dpdk]` tables are a temporary
  exception: their complete contents are silently ignored until the migration TODO is resolved.
- Unselected backend tables must not change the effective Config for the selected backend.
- The final `Config` retains only the selected backend's parsed config plus backend-neutral `CacheConfig`; it does not retain parsed config from unselected backend tables.

Minimum hard validation:

- `backend` must be exactly `"ebpf"` or `"dpdk"`.
- Missing required TOML fields are errors; Config Loader must not synthesize field defaults.
- Hard validation stops at the first error.
- The selected eBPF backend table must exist and contain its required fields. DPDK has no required TOML table.
- The unselected backend's table may be missing or incomplete.
- An unselected eBPF table is never required to become a valid `EbpfConfig`.
- `[cache]` must exist and contain its required fields.
- `ebpf.arena_pages` must be at least `1024`.
- `ebpf.cleanup_interval` must be greater than zero and use only `ms`, `s`, or `m`.
- `ebpf.packet_poll_timeout`, when present, must be between `1ms` and `1s`.
- `cache.max_entries` must be greater than zero.
- `cache.max_response_bytes` must be from 128 through 512 bytes.
- `cache.cache_negative` must be a boolean.
- `cache.max_pending_queries` must be greater than zero.
- `cache.pending_query_timeout` must be a duration from 100ms through 10s.
- Unknown keys produce warnings and are ignored; they are not hard validation failures.

Diagnostic format examples:

- `error: missing required key ebpf.cleanup_interval`
- `error: invalid duration ebpf.cleanup_interval: expected positive duration with unit ms, s, or m`

Verification:

- Config unit tests for valid eBPF config, DPDK selection without a DPDK table, temporary silent handling of obsolete
  DPDK fields, missing required fields, packet poll timeout default and bounds, bad duration, diagnostic field paths,
  direct-open file failure mapping, `ConfigError` path retention, unknown-key warning before missing-field error, and
  first-hard-error behavior.
- Config unit tests must assert that unselected backend config is not retained in the returned `Config`.
- `meson compile -C build`
- `meson test -C build`

Implementation result:

- Added C++23 `src/config/` with typed `Config`, selected-backend-only `BackendConfig`, typed `ConfigError`, injectable diagnostics, TOML loader, and temporary `to_legacy_env()` adapter.
- Hardened `CacheConfig` and `EbpfConfig` as factory-constructed value objects, centralizing their numeric and duration
  invariants while keeping TOML syntax and diagnostic formatting in Config Loader.
- Added `tomlplusplus` Meson fallback wrap.
- Added `tests/unit/config/config_loader_test.cc` using Catch2 through `catch2-with-main`.
- Focused verification passes with LeakSanitizer disabled in this managed environment: `ASAN_OPTIONS=detect_leaks=0 build/tests/unit/config_loader_test`.

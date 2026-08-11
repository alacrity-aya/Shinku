# New Config Schema with TOML Source

Shinku will introduce a new C++ Config Schema instead of treating the existing CLI flags as the canonical model. Configuration comes from a TOML Config File selected by `shinku run [--config path/to/file.toml]` until after the DPDK backend lands; env vars are not read in this phase. If no path is provided, the default Config File is `./shinku.toml`. The model is one top-level `Config` with simple top-level TOML tables `[ebpf]`, `[dpdk]`, and `[cache]`, validated according to the selected backend by an independent `src/config/` Config Loader. The parser dependency is `toml++`, and the public Config Loader API is `load_config(path, sink)`.

**Considered Options**

- Preserve the existing CLI shape as the canonical configuration model.
- Use a thin CLI subcommand to select the TOML Config File.
- Introduce env var support before DPDK.
- Use `std::variant<EbpfConfig, DpdkConfig>` for backend-specific configuration.
- Use one top-level `Config` with optional backend sections and explicit validation.
- Use a TOML Config File with one top-level `Config`, optional backend sections, and backend-neutral cache policy.
- Use `toml++` as the TOML parser dependency.
- Use simple top-level tables instead of nesting backend sections under `[backend.ebpf]` and `[backend.dpdk]`.
- Treat duration fields such as `cleanup_interval` as validated duration strings.
- Warn and ignore unknown TOML keys instead of failing startup.
- Keep config diagnostics in Config Loader instead of making `src/cli` understand TOML schema details.
- Use a minimal typed config error enum: `FileNotFound`, `ReadError`, `ParseError`, `SchemaError`, `ValidationError`, and `UnsupportedBackend`.
- Use an injectable `DiagnosticSink` owned by Config Loader, with a default `stderr` sink.
- Keep Config parsing in `src/config/`, not under `src/cli/`.
- Provide a temporary `to_legacy_env(config)` adapter for the old eBPF loader until the eBPF Backend Module replaces it.
- Allow unselected backend tables to exist without requiring them to be complete.
- Do not retain unselected backend config in the returned `Config`.
- Do not synthesize TOML field defaults in the MVP.
- Emit unknown-key warnings before hard validation and return on the first hard validation error.
- Include TOML field paths in schema and validation diagnostics.
- Keep CLI selection strict in the MVP: only `shinku run` and `shinku run --config path` are accepted.
- Split diagnostics by responsibility: CLI reports CLI syntax errors, Config Loader reports Config File diagnostics.
- Represent CLI parsing output as a typed `CliCommand` containing only the selected Config File path.
- Keep CLI parser files small: `cli.h`, `cli.cc`, and a temporary `main.cc` composition point.
- Use a small typed `CliErrorCode` set for MVP CLI syntax failures.
- Support `shinku --help`, `shinku run --help`, and `shinku --version`; version comes from Meson `configuration_data()`.
- Leave empty `--config` paths to Config Loader and do not canonicalize config paths in CLI.
- Map missing and duplicate `--config` arguments rejected by argparse to `UnexpectedArgument`.
- Open Config Files directly without a preflight `exists()` check; retain the path in `ConfigError`.

**Consequences**

The new schema can serve both eBPF and DPDK without forcing DPDK into legacy CLI assumptions. Validation becomes mandatory so startup fails clearly when the selected backend lacks required parameters, receives contradictory settings, or contains malformed duration strings. The canonical backend selector is the TOML field `backend = "ebpf" | "dpdk"`; env hooks must stay inert until intentionally introduced. The first implementation does not search `/etc`, XDG paths, or env-provided paths. Config Loader opens the provided path directly without a preflight `exists()` check, maps open/read failures to typed errors, and retains the path in `ConfigError`. Unknown TOML keys are non-fatal and must be reported as warnings before being ignored, including inside unselected backend tables. After TOML parse succeeds, Config Loader emits unknown-key warnings before hard validation; hard validation returns on the first error in the MVP. Schema and validation diagnostics include TOML field paths such as `ebpf.cleanup_interval`. Unselected backend tables are allowed for convenience, but they do not become part of the returned `Config`. The Config File path may default to `./shinku.toml`, but TOML fields themselves are explicit-only in the MVP. `src/cli` stays thin and strict: it accepts run/help/version MVP forms, reports only CLI syntax errors, returns a typed CLI result, and maps success or failure to process exit. It leaves empty `--config` paths and path resolution to Config Loader. Version text comes from Meson `configuration_data()`. CLI does not own schema validation or config-specific error formatting. `src/cli/main.cc` is a temporary composition point until Process-control and Backend Interface modules move runtime concerns out. Old `src/cli/config.c` and `src/cli/config.h` are not carried forward as the Config authority. A temporary legacy adapter keeps the current eBPF loader runnable, but it is not the canonical model and should be removed once the eBPF Backend Module owns eBPF lifecycle. Tests can capture Config diagnostics through a fake `DiagnosticSink` instead of redirecting global `stderr`.

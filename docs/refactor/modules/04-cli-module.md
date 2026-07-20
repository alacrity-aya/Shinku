# Module 4: CLI Module

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

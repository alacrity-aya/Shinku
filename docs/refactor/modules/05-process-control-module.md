# Module 5: Process-control Module

Goal:

- Isolate process signal handling from CLI and Backend code.

Scope:

- Convert `SIGINT`/`SIGTERM` into shutdown requests.
- Do not own Config loading, Backend selection, Backend lifecycle, or diagnostics.
- Implement this as an independent module, not under `src/cli/` or the legacy runtime bridge.
- Expose Process Control through a `ProcessControl` C++ class in the MVP.
- `ProcessControl` is a process-wide singleton because POSIX signal handlers need process-global reachable state.
- Shutdown requests are sticky: once requested, they remain requested until explicitly reset by tests.
- Repeated signals do not need counting and signal source does not need to be retained.
- `install_signal_handlers()` returns `std::expected<void, ProcessControlError>` so startup can fail explicitly if `sigaction()` fails.
- Test reset is hidden from the production API through a dedicated test-access helper.
- The signal handler writes only a `volatile sig_atomic_t` shutdown flag.
- The module layout is `src/process_control/process_control.h`, `process_control.cc`, `process_control_error.h`, and `process_control_test_access.h`.
- `install_signal_handlers()` is idempotent.
- The MVP does not restore previous signal handlers.
- `ProcessControlError` carries a typed code, `std::error_code`, and human-readable message.

Verification:

- Unit test or small smoke test for shutdown request state.
- Tests do not need to raise real POSIX signals when direct request/reset coverage proves the module state contract.
- `meson test -C build`

Implementation result:

- Added independent `src/process_control/` C++23 module with `ProcessControl`, `ProcessControlError`, and test-only reset access.
- `ProcessControl` is a singleton and installs `SIGINT`/`SIGTERM` handlers through `sigaction()`.
- The legacy eBPF runner no longer installs process signal handlers. It receives a C callback for shutdown state while it remains behind the temporary C ABI bridge.
- `src/cli/main.cc` installs signal handlers before entering the legacy eBPF runner and reports installation failures as startup errors.
- Added Catch2 `tests/unit/process_control/process_control_test.cc`.
- Focused verification passes with LeakSanitizer disabled in this managed environment: `ASAN_OPTIONS=detect_leaks=0 meson test -C build --no-rebuild "Process Control Test" "CLI Parser Test" "Config Loader Test"`.

# Module 6: Backend Interface Module

Goal:

- Define the C++ Backend lifecycle contract.

Scope:

- Place the first backend abstraction in `src/backend/`.
- Use the minimum file split for Module 6: `backend.h`, `backend_error.h`, `backend_runner.h`, and `backend_runner.cc`.
- Interface uses `probe()`, `start()`, `poll()`, and `stop()`.
- Public interface uses a normal pure virtual `Backend` class. CRTP is not part of the public abstraction; it may be used later only as an implementation helper if it removes real duplication.
- `BackendRunner` owns the common lifecycle state machine. Backend implementations own resource actions, not state sequencing policy.
- `BackendRunner` exposes `BackendState state() const noexcept` as the read-only lifecycle state query.
- `probe()` has no persistent side effects and returns `std::expected<void, BackendError>`.
- A successful `probe()` means the selected backend is supported on the current host with the validated Config.
- Unsupported capability, permission, wrong-config, and probe execution failures are all returned as typed `BackendError` values with human-readable messages.
- `BackendRunner::start()` calls `probe()` before acquiring backend resources.
- `Backend` destructor does not call `stop()`. Lifecycle shutdown is explicit through `BackendRunner`.
- Backend implementations report lifecycle failures through `std::expected`, not exceptions.
- `BackendRunner` destructor performs best-effort `stop()` and discards the returned status because destructors cannot report typed errors.
- `BackendRunner::probe()` is invalid while running and returns `InvalidState`.
- If `BackendRunner::start()` gets any probe error, the runner enters `Failed` and propagates the same `BackendError`.
- Module 6 initially defines explicit `BackendRunner::stop()` from `Failed` to call backend `stop()` best-effort and transition to `Stopped` if cleanup succeeds. Module 7 supersedes this state outcome for errors handled inside `run()`: cleanup and lifecycle outcome are tracked separately, and a runtime failure remains `Failed` after successful cleanup.
- Module 6 originally required `poll()` to return quickly and report `NoWork` when idle. ADR-0023 later clarifies this
  as one bounded Backend Poll Quantum, which may include a bounded backend-native readiness wait. ADR-0047 later removes
  the unused activity result.
- The current `poll()` interface returns `std::expected<void, BackendError>`.
- `PollFailed` moves `BackendRunner` into `Failed` for the MVP.
- `stop()` is idempotent. Calling `stop()` when already stopped returns success.
- Construction receives a `BackendConfig` variant.
- `BackendRunner` owns the backend via `std::unique_ptr<Backend>`.
- Module 6 does not implement a production `BackendFactory`; introduce backend creation in Module 7 when a real C++ eBPF Backend exists.

Verification:

- Fake backend tests for lifecycle sequencing, successful poll completion, and poll failure.
- `meson test -C build`

Result:

- Added `docs/adr/0009-backend-interface-runner.md`.
- Added `src/backend/` with the pure virtual `Backend` interface, typed backend errors, poll/status types, and `BackendRunner`.
- Added fake backend Catch2 coverage in `tests/unit/backend/backend_runner_test.cc`.
- Registered `Backend Runner Test` in Meson without wiring production runtime to the new interface yet.
- Removed an unrelated stale TODO comment from `src/process_control/process_control.h` as part of this module cleanup.
- `meson compile -C build` passes on 2026-07-19.
- `ASAN_OPTIONS=detect_leaks=0 meson test -C build --no-rebuild "Backend Runner Test"` passes.
- `ASAN_OPTIONS=detect_leaks=0 meson test -C build --no-rebuild "Process Control Test"` passes.
- `ASAN_OPTIONS=detect_leaks=0 meson test -C build --no-rebuild` reports 8/11 passing. Remaining failures are the known legacy baseline: `Arena List Test`, `Arena Hash Table Test`, and `Cache Store Correctness Test`.
- On 2026-07-20, simplified `probe()` to `std::expected<void, BackendError>`: successful probe means supported, and unsupported capability, permission, wrong-config, and probe execution failures all return typed `BackendError`.
- On 2026-07-20, `meson compile -C build` and `ASAN_OPTIONS=detect_leaks=0 meson test -C build --no-rebuild "Backend Runner Test"` pass after the probe/error update.
- On 2026-07-20, `ASAN_OPTIONS=detect_leaks=0 meson test -C build --no-rebuild` remains at the known 8/11 baseline with `Arena List Test`, `Arena Hash Table Test`, and `Cache Store Correctness Test` failing.

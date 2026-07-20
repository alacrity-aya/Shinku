# Module 1: Build/Test Baseline

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

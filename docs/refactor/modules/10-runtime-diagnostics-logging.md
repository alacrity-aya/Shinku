# Module 10: Runtime Diagnostics/Logging

Goal:

- Centralize runtime diagnostics and logging after eBPF and DPDK backend boundaries stabilize.

Scope:

- Design a Host Runtime diagnostics/logging boundary for operator-facing lifecycle messages, backend warnings, libbpf/C-boundary diagnostics, and BPF ring log output.
- Use the `spdlog` 1.17.0 implementation selected in Module 9; this module owns its common logger lifetime, injection,
  routing, formatting, and migration policy rather than selecting another logging library.
- Do not introduce a process-global singleton logger by default. Prefer explicit dependency injection or a narrow runtime diagnostics sink unless the module design proves a singleton is necessary.
- Keep Config diagnostics separate from runtime diagnostics unless a later decision intentionally unifies them.
- Preserve typed errors as the control-flow mechanism; logging must not replace `std::expected` results.
- Decide how low-level C boundary output migrates away from direct `printf()`/`fprintf()` calls.
- Decide how BPF ring log events map into the runtime diagnostics boundary without reintroducing the deleted Observability Surface.
- Revisit DPDK runtime Link State monitoring after Module 9's one-time startup observation, including polling versus LSC
  callbacks, PMD capability fallback, query-failure policy, and shutdown ordering.

Rationale:

- The current codebase writes diagnostics through a mix of `std::print`, `printf()`, `fprintf()`, `perror()`, `libbpf_set_print()`, Config `DiagnosticSink`, and BPF ring log callbacks.
- Module 7 needs a minimal local warning for non-fatal eBPF log-ring poll errors, but introducing a global logger during the eBPF Backend Module would expand scope and couple lifecycle refactoring to logging architecture.
- The diagnostics boundary should be designed after both backend interfaces are stable enough to reveal common runtime needs.
- Module 9 selects and introduces `spdlog` only for minimal synchronous DPDK lifecycle logging. That dependency choice
  and its direct use of spdlog's global convenience functions do not settle Module 10's final common ownership model or
  pull the rest of this module into Module 9.

Verification:

- Focused unit tests for runtime diagnostics routing once the module is designed.
- Existing Config diagnostics tests continue to pass.

# Module 10: Runtime Diagnostics/Logging

Goal:

- Centralize runtime diagnostics and logging after eBPF and DPDK backend boundaries stabilize.

Scope:

- Design a Host Runtime diagnostics/logging boundary for operator-facing lifecycle messages, backend warnings, libbpf/C-boundary diagnostics, and BPF ring log output.
- Do not introduce a process-global singleton logger by default. Prefer explicit dependency injection or a narrow runtime diagnostics sink unless the module design proves a singleton is necessary.
- Keep Config diagnostics separate from runtime diagnostics unless a later decision intentionally unifies them.
- Preserve typed errors as the control-flow mechanism; logging must not replace `std::expected` results.
- Decide how low-level C boundary output migrates away from direct `printf()`/`fprintf()` calls.
- Decide how BPF ring log events map into the runtime diagnostics boundary without reintroducing the deleted Observability Surface.

Rationale:

- The current codebase writes diagnostics through a mix of `std::print`, `printf()`, `fprintf()`, `perror()`, `libbpf_set_print()`, Config `DiagnosticSink`, and BPF ring log callbacks.
- Module 7 needs a minimal local warning for non-fatal eBPF log-ring poll errors, but introducing a global logger during the eBPF Backend Module would expand scope and couple lifecycle refactoring to logging architecture.
- The diagnostics boundary should be designed after both backend interfaces are stable enough to reveal common runtime needs.

Verification:

- Focused unit tests for runtime diagnostics routing once the module is designed.
- Existing Config diagnostics tests continue to pass.

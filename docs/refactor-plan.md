# Shinku Refactor Plan

Status: canonical execution plan entrypoint for the C++/DPDK refactor. The module sequence lives here; detailed module plans and confirmed decisions are split into linked files under `docs/refactor/`.

## How to Use This Plan

- Refactor one module at a time.
- Do not make implementation decisions for later modules until that module becomes active.
- Before editing code, read the active module file, [confirmed decisions](refactor/decisions.md), and relevant ADRs in `docs/adr/`.
- After each module, run its verification commands and update the module status in this file and the module result section.
- Keep the eBPF Backend runnable unless the selected host is explicitly unsupported, such as missing usable BPF arena support.

## Module Sequence

| Order | Module | Status | Purpose |
|---:|---|---|---|
| 1 | [Build/Test Baseline](refactor/modules/01-build-test-baseline.md) | complete | Establish the current build and test state before behavior changes. |
| 2 | [Observability Removal](refactor/modules/02-observability-removal.md) | complete | Delete current observability/degraded/event-bus surface while preserving operational loops. |
| 3 | [Config Module](refactor/modules/03-config-module.md) | complete | Add C++23 TOML Config Loader, validation, typed errors, and diagnostics. |
| 4 | [CLI Module](refactor/modules/04-cli-module.md) | complete | Reduce CLI to `shinku run [--config path]` config-file selection. |
| 5 | [Process-control Module](refactor/modules/05-process-control-module.md) | complete | Move signal handling and shutdown request propagation out of CLI/backend code. |
| 6 | [Backend Interface Module](refactor/modules/06-backend-interface-module.md) | complete | Introduce C++ Backend lifecycle interface and shared status/result types. |
| 7 | [eBPF Backend Module](refactor/modules/07-ebpf-backend-module.md) | complete | Adapt existing eBPF loader behind the Backend interface and keep it runnable. |
| 8 | [Cache/DNS Module](refactor/modules/08-cache-dns-module.md) | implementation complete (PERF-M8-1 deferred TODO) | Separate backend-neutral DNS/cache policy from eBPF storage details. |
| 9 | [DPDK Backend Module](refactor/modules/09-dpdk-backend-module.md) | in progress | Implement the DPDK backend after common interfaces are stable. |
| 10 | [Runtime Diagnostics/Logging](refactor/modules/10-runtime-diagnostics-logging.md) | pending | Centralize operator-facing diagnostics, warnings, and runtime logging after backend boundaries stabilize. |
| 11 | [Test Suite Rewrite](refactor/modules/11-test-suite-rewrite.md) | pending | Rewrite unreliable legacy tests into module-focused regression tests as refactored modules stabilize. |

Current active module:

- [Module 9: DPDK Backend Module](refactor/modules/09-dpdk-backend-module.md)
- Completed slice: 9A DPDK Transport and Lifecycle. Native EAL arguments after `--`, fixed Port 0/1 roles, one-lcore
  cooperative forwarding, EAL/ethdev/queue/pool ownership, and the production `net_ring` smoke pass. Physical PCI
  evidence remains unexecuted because the development host has no suitable interfaces.
- Active slice: 9B DPDK Cache Path.
- Completed slice: 8A eBPF Resource Ownership (`EbpfNativeSession` design).
- Completed slice: 8B Backend-neutral Cache Domain.
- Completed slice: 8C DNS Policy Engine.
- Completed slice: 8D eBPF Cache Store. Host Store, shared ABI, layout, fingerprint, Cache Hit vectors, Cache Time boundaries, and the privileged verifier feasibility gate pass on the MVP development host.
- Completed implementation slice: 8E eBPF production cutover. The correlated XDP/TC packet path, fixed event ABI, synchronous Host Fill, Pending cleaner, operational shutdown loops, strict legacy deletion, root namespace integration, fuzz smoke, and Docker soak evidence are recorded in the Module 8 plan. The frozen `PERF-M8-1` harness and privileged smoke are complete. Canonical performance evidence is retained as a deferred TODO and does not block starting Module 9; no product performance blocking line is set.

Deferred TODO carried forward:

- Execute and archive the canonical five-round `PERF-M8-1` artifact after the DPDK backend work reaches a stable comparison point. Existing non-canonical artifacts remain exploratory evidence only.

## Test Policy During Refactor

- The legacy test suite is not a reliable quality gate. It has environment-sensitive sanitizer failures and uneven coverage.
- Existing test results are recorded as baseline signals, not as proof of product correctness.
- Do not spend effort preserving tests for modules that are intentionally deleted, such as current observability, degraded mode, and event bus tests.
- Each rewritten module should gain focused tests for its new contract.
- The broader legacy test suite is rewritten as a dedicated module after the runtime boundaries stabilize.
- Do not migrate the whole legacy suite to a C++ framework as part of CLI/Config. New C++ module tests use Catch2 because the current tests are executable-focused, module-local, and do not need mocks or fixtures heavy enough to justify GTest.

## Decision Reference

- [Confirmed decisions and grill queue](refactor/decisions.md)
- [Benchmark decision backlog](refactor/benchmark-backlog.md)
- [Deferred feature backlog](refactor/deferred-features.md)
- [ADR index](adr/)

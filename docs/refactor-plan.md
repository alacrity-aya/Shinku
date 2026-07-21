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
| 8 | [Cache/DNS Module](refactor/modules/08-cache-dns-module.md) | pending | Separate backend-neutral DNS/cache policy from eBPF storage details. |
| 9 | [DPDK Backend Module](refactor/modules/09-dpdk-backend-module.md) | pending | Implement the DPDK backend after common interfaces are stable. |
| 10 | [Runtime Diagnostics/Logging](refactor/modules/10-runtime-diagnostics-logging.md) | pending | Centralize operator-facing diagnostics, warnings, and runtime logging after backend boundaries stabilize. |
| 11 | [Test Suite Rewrite](refactor/modules/11-test-suite-rewrite.md) | pending | Rewrite unreliable legacy tests into module-focused regression tests as refactored modules stabilize. |

Current active module:

- [Module 8: Cache/DNS Module](refactor/modules/08-cache-dns-module.md)

## Test Policy During Refactor

- The legacy test suite is not a reliable quality gate. It has environment-sensitive sanitizer failures and uneven coverage.
- Existing test results are recorded as baseline signals, not as proof of product correctness.
- Do not spend effort preserving tests for modules that are intentionally deleted, such as current observability, degraded mode, and event bus tests.
- Each rewritten module should gain focused tests for its new contract.
- The broader legacy test suite is rewritten as a dedicated module after the runtime boundaries stabilize.
- Do not migrate the whole legacy suite to a C++ framework as part of CLI/Config. New C++ module tests use Catch2 because the current tests are executable-focused, module-local, and do not need mocks or fixtures heavy enough to justify GTest.

## Decision Reference

- [Confirmed decisions and grill queue](refactor/decisions.md)
- [ADR index](adr/)

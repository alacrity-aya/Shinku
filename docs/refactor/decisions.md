# Confirmed Refactor Decisions

This file is the stable entrypoint for confirmed refactor decisions. Decisions are split by module or architectural
stage so the active work does not require loading the complete decision history.

Before code edits, read the active module plan, its decision file below, and the relevant ADRs under `docs/adr/`.
Historical Segment numbers remain stable because existing decisions refer to them.

| Scope | Decisions |
|---|---|
| Refactor context, goals, code facts, and cadence | [Overview](decisions/overview.md) |
| Segments 1-4: scope, C++ migration, Domain Model, and lifecycle foundations | [Foundation](decisions/foundation.md) |
| Segments 5-9: Config Schema, Config Loader, and CLI | [Config and CLI](decisions/config-cli.md) |
| Segments 10-15: Backend interface, Runtime loops, Process Control, and diagnostics deferral | [Runtime and Backend](decisions/runtime-backend.md) |
| Segment 16: Module 8A eBPF resource ownership | [Module 8A](decisions/module-08a-ebpf-resource-ownership.md) |
| Segment 17: Module 8B backend-neutral Cache Domain | [Module 8B](decisions/module-08b-cache-domain.md) |
| Segment 18: Module 8 MVP ECS scope and Query Correlation foundations | [Module 8 ECS Scope](decisions/module-08-ecs-scope.md) |
| Segment 19: Module 8C DNS Policy | [Module 8C](decisions/module-08c-dns-policy.md) |
| Segment 19: Module 8D eBPF Cache Store | [Module 8D](decisions/module-08d-ebpf-cache-store.md) |
| Segment 20: Module 8E eBPF production cutover | [Module 8E](decisions/module-08e-production-cutover.md) |
| Segment 20: Module 8E design review findings | [Module 8E Review](decisions/module-08e-design-review-findings.md) |
| Module 8 performance evidence | [PERF-M8-1](decisions/module-08-performance-evidence.md) |
| Segment 21: Module 9 DPDK Backend | [Module 9](decisions/module-09-dpdk-backend.md) |

New decisions belong in the narrowest applicable file. Cross-module decisions should be recorded in the earliest
owning stage and linked from later module decisions when they refine or supersede it.

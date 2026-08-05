# Keep eBPF Backend Runnable During Refactor

Shinku will keep the current eBPF Backend runnable while adding the DPDK Backend. eBPF is no longer the only architecture driver, but it remains a working backend and regression target during the C++ migration.

**Current Qualification (Module 8E)**

[Module 8E's production-cutover contract](../refactor/decisions/module-08e-production-cutover.md) supersedes this ADR's requirement to preserve individual "existing eBPF tests." The Operational Loops and a runnable eBPF Backend remain mandatory, but legacy implementations, tests, benchmarks, and results have no preservation entitlement. Retain or rewrite an artifact only when it proves the current Contract; strict semantic deletion removes obsolete artifacts during the atomic cutover. This ADR otherwise remains as the historical rationale for keeping the Backend runnable.

**Considered Options**

- Freeze eBPF as an unsupported extension interface while building DPDK.
- Remove eBPF temporarily and restore it after DPDK works.
- Keep eBPF runnable and introduce the Cache Engine abstraction around it.

**Consequences**

The refactor must preserve BPF build, skeleton generation, attach/detach, ring polling, cache cleanup, and, subject to the Module 8E qualification above, eBPF regression evidence. This slows the backend abstraction work, but prevents losing the only currently working packet path. Keeping eBPF runnable does not imply a compatibility-store fallback: if the selected eBPF backend lacks required BPF arena support on the target kernel, startup fails as unsupported.

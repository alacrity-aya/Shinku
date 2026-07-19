# Keep eBPF Backend Runnable During Refactor

Shinku will keep the current eBPF Backend runnable while adding the DPDK Backend. eBPF is no longer the only architecture driver, but it remains a working backend and regression target during the C++ migration.

**Considered Options**

- Freeze eBPF as an unsupported extension interface while building DPDK.
- Remove eBPF temporarily and restore it after DPDK works.
- Keep eBPF runnable and introduce the Cache Engine abstraction around it.

**Consequences**

The refactor must preserve BPF build, skeleton generation, attach/detach, ring polling, cache cleanup, and existing eBPF tests. This slows the backend abstraction work, but prevents losing the only currently working packet path. Keeping eBPF runnable does not imply a compatibility-store fallback: if the selected eBPF backend lacks required BPF arena support on the target kernel, startup fails as unsupported.

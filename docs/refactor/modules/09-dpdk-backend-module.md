# Module 9: DPDK Backend Module

Goal:

- Add the DPDK Backend after common runtime, config, and cache interfaces are stable.

Scope:

- Implement minimum configured `client_port` and `server_port` behavior first.
- Keep eBPF backend runnable.
- Do not reintroduce observability unless explicitly scoped later.

Verification:

- DPDK build path.
- DPDK-specific smoke tests where available.
- Existing eBPF/cache/parser tests still pass.

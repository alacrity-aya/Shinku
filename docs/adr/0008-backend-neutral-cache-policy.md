# Backend-neutral Cache Policy

Shinku will place Cache Policy in a top-level backend-neutral `cache` section of the TOML Config File. Backend sections should contain packet I/O and resource settings, while DNS cache semantics such as TTL bounds, response-size limits, negative caching, admission, and eviction apply consistently across eBPF and DPDK.

**Considered Options**

- Put cache settings under `ebpf.cache` and `dpdk.cache`.
- Keep all cache policy hardcoded until DPDK lands.
- Use a top-level backend-neutral `cache` section.

**Consequences**

The two backends remain one product with the same DNS cache semantics. Backend-specific tuning can still be added later through an explicit ADR, but the default model avoids semantic drift between eBPF and DPDK.

# Module 8: Cache/DNS Module

Goal:

- Separate backend-neutral DNS/cache policy from eBPF-specific storage details.

Scope:

- Preserve DNS parsing, ECS behavior, cache admission/eviction, negative caching, TTL behavior, and arena safety semantics.
- Do not design DPDK-specific behavior here beyond what the backend-neutral interface requires.

Verification:

- DNS parser tests.
- Cache store tests.
- DNS hash tests.

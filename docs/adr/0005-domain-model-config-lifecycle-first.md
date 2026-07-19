# Domain Model Starts with Config and Backend Lifecycle

Shinku will introduce new C++ domain types first for configuration and backend lifecycle only. Host Runtime operations will return `std::expected<T, Error>` or typed status objects; exceptions and raw errno-style propagation are not the primary error model.

**Considered Options**

- Start the domain model with all concepts, including DNS parser results and cache key/value types.
- Wrap the existing C structs and defer new C++ types until after DPDK.
- Define new C++ types for configuration and backend lifecycle first, then adapt the current eBPF backend to them.

**Consequences**

The first slice is narrow enough to keep eBPF runnable while proving the C++ architecture. DPDK will not inherit the current C loader/config shape, but adapters are required until DNS and cache policy are migrated.

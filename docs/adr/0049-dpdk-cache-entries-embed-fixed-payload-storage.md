# DPDK Cache Entries Embed Fixed Payload Storage

Status: accepted

Each Module 9B MVP `DpdkCacheEntry` is self-contained. It embeds its complete physical Cache Key, timestamps and private
metadata, one 512-byte Response array, and one 45-element `uint16_t` TTL-offset array. Store startup allocates one
fixed-size, non-growing Entry array containing exactly `CacheConfig::max_entries` elements. The `DpdkCacheEntry*` values
stored by `rte_hash` therefore remain stable for the Store lifetime.

Configured `max_response_bytes` remains the Cache Admission limit but does not shrink physical Entry storage. Active
Response and TTL-offset counts bound every access. Inactive tails are non-semantic: Store and Cache Hit code do not emit,
parse, hash, or depend on them, and replacement need not clear them. Tests poison those tails to enforce the boundary.

The fixed layout deliberately trades memory density for direct access, simple ownership, and minimal MVP layout
arithmetic. Benchmark backlog `PERF-9B-2` may compare a configuration-sized split payload slab when deployment capacity
or profiling demonstrates material memory or cache-pressure cost. That optimization is not a Module 9B completion gate.

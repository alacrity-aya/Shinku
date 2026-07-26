# Cache Domain Contract Excludes the Cache Hit Path

The backend-neutral `CacheStore` interface covers Cache Fill and cleanup only and deliberately has no `lookup()` operation, because the eBPF Cache Hit Path lives in XDP where a C++ virtual call cannot reach it, and a future DPDK userspace hit path should call its own concrete Store directly rather than pay virtual dispatch per packet. Cache Hit Semantics — expiration, per-RR TTL aging, whole-second rounding, Transaction ID rebinding, and Question Section preservation — remain backend-neutral, but they are expressed as written rules plus shared Cache Hit vectors that every hit path must satisfy, instead of as shared code.

**Considered Options**

- Add `lookup()` to the virtual interface and let the eBPF Store implement it as never-called.
- Leave hit behavior entirely to each Backend with no shared specification.
- Contract covers fill and cleanup; hit semantics are specified and verified by shared vectors.

**Consequences**

Nothing backend-neutral sits on any per-packet path. The cost is that hit semantics are enforced by test data rather than by the type system, so the vectors under `tests/vectors/cache_hit/` have to be written in Module 8B, before the first hit path exists — written afterwards they would merely transcribe whatever XDP already does. A cache interface without a lookup operation is surprising enough that a future reader will otherwise assume it is an oversight.

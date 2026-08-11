# DPDK Cache Uses rte_hash and Preallocated Entries

Status: accepted

The Module 9B MVP concrete Cache Store uses one DPDK `rte_hash` index from a complete fixed-length physical Cache Key
to a stable `DpdkCacheEntry*` in a startup-preallocated fixed-capacity Entry slab. `rte_hash` owns and compares its copy
of the key; its associated data is only a non-owning pointer. Shinku owns every Entry and all response, TTL-offset,
replacement, and cleanup storage for the Backend lifetime.

The physical key explicitly serializes Cache Namespace, QTYPE, QCLASS, canonical QNAME length, and the complete
canonical QNAME into a zero-filled byte-order-stable buffer. It does not hash a C++ object representation with implicit
padding and does not use a fingerprint as Cache identity. Each occupied Entry retains the physical key needed for hash
deletion. Cache Hit and Cache Fill perform no general heap allocation after successful startup.

This representation prioritizes bounded ownership and exact Cache Key equality over minimum key width. A compact
fingerprint index or a custom fixed-capacity open-addressing table may be faster, but either adds collision or table
state that is not justified without measurement. Benchmark backlog `PERF-9B-1` owns that comparison. An alternative
must preserve complete-key equality and the unchanged Cache Hit, Store, capacity, cleanup, and Fail-open contracts; a
probabilistic fingerprint match alone can never authorize a Cache Hit.

ADR-0049 fixes the MVP Entry's internal payload storage while retaining this index and ownership model.

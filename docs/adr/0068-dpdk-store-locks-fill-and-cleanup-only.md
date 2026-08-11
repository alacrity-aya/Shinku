# DPDK Store Locks Fill and Cleanup Only

Status: accepted

`DpdkCacheStore` owns one mutex that serializes its single `store()` caller with its potentially concurrent `cleanup()`
caller. This preserves the backend-neutral Cache Store concurrency contract and lets the DPDK concrete Store run the
unchanged conformance suite. The lock protects hash mutation, Entry ownership, free-list, replacement cursor, and
cleanup cursor state.

The direct concrete `lookup()` used by Client Packet Path does not acquire this mutex. Module 9 production execution
serializes lookup, Fill, and cleanup on the sole cooperative lcore, so the Store mutex is uncontended and never enters
the per-packet Cache Hit path. The MVP does not promise lookup concurrent with mutation; a future cleanup or packet
worker must redesign lookup publication and Entry reclamation rather than assuming this mutex is sufficient.

Pending Query state has no backend-neutral concurrent interface and remains mutex-free in the single-lcore MVP. This
decision satisfies an existing Store contract; it does not add a cleanup thread or reopen the execution model.

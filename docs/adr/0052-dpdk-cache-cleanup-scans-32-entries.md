# DPDK Cache Cleanup Scans 32 Entries

Status: accepted

The Module 9B DPDK Cache Cleanup task inspects at most 32 Entry slots in one Poll Quantum. It persists its cursor and
remaining-count state across invocations so one cleanup sequence examines exactly one capacity-wide sweep. Expired
Entries are removed from `rte_hash` and returned to the intrusive free list. Hit-time expiration checks remain
authoritative while physical reclamation is delayed.

This aligns cleanup semantics with `EbpfCacheStore` without copying its batch constant. eBPF scans at most 256 slots on
a separate CleanupWorker; DPDK Cache Cleanup shares one lcore with both packet paths, each of which receives a 32-packet
burst opportunity. A 32-Entry maintenance bound limits the uninterrupted cleanup block before the next RX opportunity.

The batch size is a private implementation constant, not Config. Benchmark backlog `PERF-9B-3` may compare larger
fixed batches only by measuring packet latency and loss together with cleanup CPU, sweep completion, expired residency,
and capacity pressure. Adaptive time-budget cleanup is not part of the MVP.

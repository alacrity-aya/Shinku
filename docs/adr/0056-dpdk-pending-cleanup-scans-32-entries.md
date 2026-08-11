# DPDK Pending Cleanup Scans 32 Entries

Status: accepted

The Module 9B DPDK Pending Cleanup task inspects at most 32 Entry slots in one Poll Quantum. It owns a persistent cursor
and remaining-count state independent of Cache Cleanup, so one cleanup sequence examines exactly one capacity-wide
sweep across bounded invocations. Active and Claimed Entries meeting the inactivity timeout are removed from `rte_hash`
and returned to the Pending free list.

When both maintenance tasks are due in the fixed scheduler order, Cache Cleanup and Pending Cleanup inspect at most 64
total slots after the two packet paths. This bound deliberately differs from the eBPF Pending Cleaner's 256-record batch,
which executes on a separate worker. Delayed reclamation affects capacity availability rather than correlation
correctness because Response handling checks timeout before changing Active to Claimed.

The batch size is private, not Config. Benchmark backlog `PERF-9B-5` may compare larger fixed batches only with packet
latency and loss, Pending pressure and correlation success, sweep completion, and total CPU measured together.

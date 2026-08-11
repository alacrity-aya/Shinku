# DPDK Store Aligns Admission with eBPF

Status: accepted

The Module 9B DPDK Store aligns its observable admission and victim-selection behavior with `EbpfCacheStore`. It
allocates a cleanup-reclaimed slot from an intrusive free list first, then the never-used Entry suffix, and only then
selects the Entry at a deterministic round-robin replacement cursor. A same-key Candidate updates its current Entry in
place and does not advance replacement selection.

Using an empty or reclaimed slot returns `Inserted`. Reusing a selected victim that is expired at Store Admission Time
also returns `Inserted`; displacing a still-hit-visible different victim returns `Replaced`. Same-key acceptance returns
`Updated`, while the shared rejection and error contracts remain unchanged. Successful selection of an occupied victim
advances the replacement cursor to the following slot.

This is semantic alignment, not physical implementation reuse. The DPDK MVP does not copy the eBPF Store's generation,
seqlock, rollback snapshot, or BPF map publication protocol. ADR-0068 retains one Store-owned mutex solely for the
shared `store()`/`cleanup()` concurrency contract; it does not enter concrete DPDK lookup. Future admission-policy
alternatives remain subject to benchmark backlog `PERF-8D-1` and must preserve the shared Store contract.

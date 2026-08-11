# DPDK Pending Stores the Complete Question

Status: accepted

The Module 9B DPDK Pending table uses one `rte_hash` whose fixed 16-byte key preserves the eBPF Query Correlation
identity: Query source/client IPv4 and UDP port, Query destination/service IPv4 and UDP port, DNS Transaction ID, and
explicit zeroed padding, all packet fields in network byte order. Question identity, ifindex, protocol, and duplicate
Cache Namespace do not enter that key. Hash data pointers refer into a startup-preallocated, non-growing array of
exactly `CacheConfig::max_pending_queries` Entries.

Each DPDK Pending Entry stores the complete canonical QNAME, QTYPE, QCLASS, state, and last-seen time. An existing
tuple-plus-ID with a different complete Question is neither overwritten nor refreshed. A Response reverses its network
tuple to locate the Entry and must compare its complete canonical Question exactly before it can consume the Pending
Query or authorize Cache Fill. A mismatch leaves the original Entry live.

This preserves eBPF's one-concurrent-exchange-per-tuple trust boundary while avoiding its BPF-driven keyed 128-bit
Question fingerprint representation. DPDK needs no Pending fingerprint secret, and probabilistic equality cannot
authorize Fill. Benchmark backlog `PERF-9B-4` may compare more compact bounded storage only if complete equality and the
same correlation behavior remain enforced.

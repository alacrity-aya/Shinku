# DPDK Cache Hit Normalizes Frame and Metadata

Status: accepted

Module 9B generates the same deterministic Cache Hit packet as the eBPF path. It swaps Query Ethernet addresses and
emits IPv4 EtherType; swaps IPv4 and UDP endpoints; emits IPv4 version/IHL 4/5, TOS zero, exact total length, ID zero,
DF set, fragment offset zero, TTL 64, UDP protocol, and a software-computed IPv4 checksum; emits exact UDP length and a
zero IPv4 UDP checksum; and applies the shared DNS Transaction ID, Question, and TTL-aging semantics.

Before client TX, the Path clears metadata inherited from RX or the Query: RX/TX offload flags, packet type, VLAN tags,
RSS/hash data, and TX-offload length fields. It preserves the mbuf's allocator and ownership fields and the exact
single-segment data layout established by ADR-0062. No checksum or other TX offload is requested.

There is one output contract for ring and PCI Device Sources. Module 9B does not select PMD-dependent checksum,
metadata, or header behavior. Cross-backend packet vectors require byte-identical eBPF and DPDK Cache Hit frames.

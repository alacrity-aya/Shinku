# DPDK Cache Hit Reuses the Query mbuf

Status: accepted

The Module 9B Client Packet Path reuses the original Query RX mbuf for a Cache Hit. Before touching that mbuf, it builds
and validates the complete Ethernet/IPv4/UDP/DNS Response in one fixed task-owned scratch buffer. The existing 512-byte
DNS bound makes the complete untagged frame at most 554 bytes. Construction includes Cache Hit Question and Transaction
ID rebinding, TTL aging, normalized headers, exact lengths, and checksum.

After construction succeeds, the Path uses the checked single-segment `rte_pktmbuf_append()` or
`rte_pktmbuf_trim()` operation to reach the exact frame length. An adjustment failure occurs before commit, leaves the
original Query unchanged, and enters the normal Cache Miss path, including Pending admission before service TX. After a
successful adjustment, or immediately when lengths match, one bounded copy replaces the complete frame and no later
construction operation may fail. The same mbuf is then submitted once toward the client.

The MVP does not allocate a second Response mbuf and does not fall back to allocation when tailroom adjustment fails.
The Frame Contract and default DPDK data room are expected to make the maximum generated frame representable; the
failure path remains explicit for ownership safety and deterministic tests.

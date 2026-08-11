# DPDK Fills Before Response TX Handoff

Status: accepted

The Module 9B Service Packet Path completes Response correlation, the `Active -> Claimed` transition, and synchronous
Cache Fill while it still owns the received RX mbuf. It parses the Response once, consumes borrowed Candidate response
and TTL-offset spans before returning from `Store::store()`, and then submits that same mbuf exactly once toward the
client.

`StoreOutcome::Inserted`, `Updated`, `Rejected`, and every operational Store error are Cache-local results. They never
block, duplicate, or alter transparent Response forwarding. TX partial acceptance remains governed by the DPDK mbuf
ownership contract; the Path does not access the mbuf after TX handoff. Post-TX reparse, a second Response copy, and an
asynchronous Fill queue are outside the MVP.

This preserves the eBPF ordering in which correlation and Fill-event publication complete before the packet leaves the
forwarding path, while using DPDK's synchronous borrowed-span contract on one lcore.

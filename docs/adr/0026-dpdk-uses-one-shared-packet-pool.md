# DPDK Uses One Shared Packet Pool

Status: accepted

Module 9 creates one shared DPDK Packet Pool on the sole MAIN lcore's NUMA socket after descriptor adjustment completes
for both ports. Both RX queues draw mbufs from this pool, forwarded packets retain their original mbufs through TX, and
9B constructs Cache Hit packets from the same pool. Pool ownership remains inside `DpdkNativeSession` and cleanup
releases it once after queues and ports stop using it.

ADR-0062 later selects in-place Cache Hit construction: the Hit path reuses the Query RX mbuf already allocated from
this pool rather than obtaining a second mbuf. The shared-pool ownership and capacity decision remains unchanged.

Capacity is computed only after both PMDs adjust their descriptor counts. The required count is all actual RX and TX
descriptors plus two 32-packet burst allowances and a fixed 256-object cache for the sole lcore. Session uses checked
arithmetic and rounds up to the smallest fitting `2^N - 1` pool size; the default two-port 1024 RX/1024 TX topology
therefore creates 8191 mbufs. Pool capacity is not Config.

Per-port and per-NUMA pools are rejected for the single-lcore MVP because they add allocation selection, naming,
capacity, partial-start, and Cache Hit ownership rules without evidence from physical hardware. A port on a remote NUMA
socket remains functionally supported but receives no locality or performance claim. Physical benchmark evidence must
record CPU, port, and Packet Pool NUMA placement before justifying a per-NUMA design.

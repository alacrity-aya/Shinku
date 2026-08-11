# DPDK Transport Forwards Cache Bypasses

Status: accepted

The DPDK Backend forwards every received Ethernet frame that satisfies the Module 9 single-segment Frame Contract
byte-for-byte to the opposite port unless the Cache Hit Path has safely answered an eligible Query. Transport
Forwarding is deliberately broader than the Cacheable Query Profile.

ARP, IPv6, TCP, non-DNS UDP, VLAN-tagged frames, malformed or unsupported DNS, and every other Cache Bypass continue
through the inline path without creating Cache Entry, Pending Query, or Cache Fill state. Cache Misses likewise preserve
the upstream path while establishing Pending state only when Query Eligibility permits it. A valid Cache Hit is the only
case that consumes a client Query and emits a generated Response instead of forwarding that Query upstream.

Module 9 does not rewrite Ethernet addresses, route packets, learn MAC addresses, apply ACLs, or become a protocol
filter. Tests cover byte preservation in both directions and prove representative non-cacheable traffic has no cache
side effects. VLAN-aware caching remains deferred, but VLAN forwarding is not blocked by that cache limitation.

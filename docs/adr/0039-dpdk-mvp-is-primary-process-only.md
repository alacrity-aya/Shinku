# DPDK MVP Is Primary-process Only

Status: superseded by ADR-0070

Each Module 9 DPDK Backend is one independent DPDK EAL primary process. `DpdkNativeSession` explicitly supplies
`--proc-type=primary`; it does not use automatic process-role detection, start as a secondary process, or expose process
type through Config.

This matches the Backend's exclusive ownership of EAL, ports, queues, Packet Pool, ring-backed ethdevs, Cache state, and
reverse-order cleanup. If primary initialization cannot establish the instance's own DPDK resource domain, startup
fails rather than attaching to resources owned by another process or silently changing lifecycle responsibility.

Supporting DPDK secondary processes is not a local EAL-argument extension. It requires a separate design for shared
memory identity, resource discovery, port and queue ownership, Cache and Pending concurrency, failure propagation, and
shutdown when one process exits. Module 9 therefore makes no multi-process compatibility claim.

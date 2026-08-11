# DPDK Backend Uses a Two-Port Transparent Topology

Status: superseded by ADR-0021

The DPDK Backend interprets `dpdk.client_port` and `dpdk.server_port` as distinct DPDK Ethernet Port IDs, not DNS UDP
ports or socket identifiers. They define the client-side and DNS-service-side boundaries of one transparent Cache Point:
Queries travel from the client-side port toward the service-side port, Responses travel in the reverse direction, and
the Backend may answer eligible Queries locally at the Cache Point. This preserves the existing Config Schema and the
Runtime Backend decision that configured DPDK port identifiers are checked by `probe()` before packet processing starts.

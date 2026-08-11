# DPDK MVP Uses Standard Single-segment Frames

Status: accepted

Module 9 supports a fixed 1500-byte L3 MTU with each packet contained in one mbuf segment. Both configured ports must
support and be configured for this common DPDK Frame Contract. The shared Packet Pool uses DPDK's default mbuf data-room
size, and RX scatter is not enabled. Failure to establish the contract on either port fails startup.

The MVP exposes no MTU field and does not support Jumbo Frames, multi-segment forwarding, segmentation, or IP
fragmentation. This keeps transparent forwarding and Packet Buffer Ownership within one mbuf while covering the
backend-neutral Cache Response Limit of at most 512 DNS bytes. Jumbo support requires later physical-device evidence and
an explicit decision about data-room cost, segment ownership, Cache Hit construction, and cross-port MTU behavior.

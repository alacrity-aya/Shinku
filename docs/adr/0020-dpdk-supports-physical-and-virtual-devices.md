# DPDK Supports Physical and Virtual Device Sources

Status: accepted

The DPDK Backend accepts typed physical PCI and virtual DPDK Device Sources while preserving one Port ID based packet
path after EAL initialization. The current development host cannot supply the two physical ports required by the
transparent topology, so Module 9 requires real packet-I/O smoke with virtual devices and deterministic fake/unit
coverage of PCI selection, failure mapping, and cleanup. The project does not report an unexecuted physical smoke as a
pass; real two-port PCI evidence remains due when suitable hardware is available. Mixed physical/virtual pairs are not
restricted: each Cache Point side independently selects a supported Device Source and uses the same post-EAL ethdev
packet path. Current hardware evidence remains limited to the virtual pair.

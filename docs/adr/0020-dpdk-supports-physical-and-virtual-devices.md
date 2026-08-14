# DPDK Supports Physical and Virtual Device Sources

Status: accepted, amended by ADR-0070

The DPDK Backend supports physical PCI and virtual DPDK devices through the same Port ID based packet path after EAL
initialization. ADR-0070 moved device selection out of typed TOML Device Sources: the launch command now supplies native
EAL allowlists, blocklists, and vdev declarations, and Shinku consumes the resulting Port 0 and Port 1.

The current development host cannot supply the two physical ports required by the transparent topology, so Module 9
requires real packet-I/O smoke with virtual devices. The project does not report an unexecuted physical smoke as a pass;
real two-port PCI evidence remains due when suitable hardware is available. The runtime packet path does not otherwise
distinguish physical and virtual devices.

# DPDK Backend Does Not Manage PCI Driver Binding

Status: accepted

Binding a physical PCI device to the kernel driver required by its DPDK PMD is a deployment prerequisite. Shinku does
not execute `dpdk-devbind`, write PCI driver sysfs attributes, load kernel modules, detach an active Linux network
interface, force every device onto `vfio-pci`, or restore a previous driver during shutdown. This avoids an application
startup side effect that could disconnect the host and avoids incorrectly rebinding devices used by bifurcated PMDs.

The deployment environment prepares each configured BDF according to the selected PMD and grants the process the
required VFIO, IOMMU, device, and memory permissions. `DpdkNativeSession` limits its responsibility to passing configured
PCI identities to EAL, resolving the resulting ethdev Port IDs, and owning resources acquired after successful EAL
initialization.

If EAL cannot probe a configured PCI Device Source, Backend startup returns `StartFailed`. The error identifies the BDF,
retains the available DPDK error, and tells the operator to verify driver binding, permissions, IOMMU/VFIO state, and PMD
availability. Failure does not trigger an automatic binding attempt or mutate host driver state during cleanup.

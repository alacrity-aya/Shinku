# DPDK Backend Does Not Manage PCI Driver Binding

Status: accepted

Binding a physical PCI device to the kernel driver required by its DPDK PMD is a deployment prerequisite. Shinku does
not execute `dpdk-devbind`, write PCI driver sysfs attributes, load kernel modules, detach an active Linux network
interface, force every device onto `vfio-pci`, or restore a previous driver during shutdown. This avoids an application
startup side effect that could disconnect the host and avoids incorrectly rebinding devices used by bifurcated PMDs.

The deployment environment prepares each selected PCI device according to the selected PMD and grants the process the
required VFIO, IOMMU, device, and memory permissions. The launch command passes any required native PCI allowlist or
blocklist arguments to EAL. `DpdkNativeSession` owns only the resources acquired after successful EAL initialization.

If EAL cannot initialize the requested device set, Backend startup returns `StartFailed` and retains the available DPDK
error. The operator remains responsible for checking the launch arguments, driver binding, permissions, IOMMU/VFIO
state, and PMD availability. Failure does not trigger an automatic binding attempt or mutate host driver state during
cleanup.

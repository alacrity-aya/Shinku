# DPDK EAL Probes Only Configured PCI Devices

Status: accepted

The validated client-side and service-side Device Sources define the complete set of PCI devices Shinku permits EAL to
probe. `DpdkNativeSession` generates one EAL allowlist entry for every configured PCI BDF and never emits an unrelated
device identity. A PCI/PCI topology therefore allowlists two distinct BDFs, a mixed topology allowlists one, and a
ring/ring topology passes `--no-pci`.

Shinku does not let EAL scan all available PCI devices and select the configured ports afterward. This keeps startup
independent from unrelated host hardware, avoids initializing devices owned by another application, and makes the
Effective Config the sole device-selection authority. Module 9 does not expose probe-all, blocklist, or raw EAL
allowlist fields.

After EAL initialization, each configured PCI identity must resolve to exactly one ethdev. Missing, duplicate, or
unexpected resolution returns `StartFailed` and follows the normal reverse-order partial-start cleanup path. Ring Device
Sources are created explicitly after EAL according to ADR-0036 and do not widen PCI discovery.

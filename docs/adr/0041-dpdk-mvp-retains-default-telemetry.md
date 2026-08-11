# DPDK MVP Retains Default Telemetry

Status: accepted

Module 9 retains DPDK's default Telemetry service. `DpdkNativeSession` does not supply `--no-telemetry`, allowing EAL to
create its standard telemetry socket under the fixed `shinku` runtime directory and expose commands registered by the
linked DPDK libraries and PMDs.

Shinku does not register application-specific telemetry commands, add a telemetry client to the Backend interface, or
promise that DPDK command names and response schemas are stable Shinku contracts. Telemetry is supplementary native
diagnostic access; typed `BackendError` values remain lifecycle control flow and `spdlog` remains the source of the
small Module 9 lifecycle log set.

Socket creation, path permissions, client authorization, and native command availability remain deployment and DPDK
runtime facts. Module 10 may later evaluate DPDK Telemetry as an explicit Runtime Diagnostics adapter and document any
supported subset rather than retroactively treating all native commands as Shinku interface.

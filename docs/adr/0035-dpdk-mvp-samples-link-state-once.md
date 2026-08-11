# DPDK MVP Samples Link State Once

Status: accepted

Module 9 performs one nonblocking Link State observation for each configured port during `DpdkBackend::start()`, after
EAL initialization, runtime Port ID resolution, queue and Packet Pool setup, `rte_eth_dev_start()`, and promiscuous-mode
verification have succeeded. It calls `rte_eth_link_get_nowait()` once per port and records the initial up/down result
through `spdlog`. A reported down state does not fail startup, wait for negotiation, or change Backend Lifecycle state.

This observation is deliberately not implemented in `Backend::probe()`. That lifecycle operation runs before EAL owns
the devices and before configured Device Sources have runtime Port IDs, so it cannot reliably query ethdev Link State
without violating the side-effect-free Probe contract. The term Link State probe refers only to this one startup
observation inside `start()`.

After the initial observation, Module 9 performs no periodic Link State query, registers no
`RTE_ETH_EVENT_INTR_LSC` callback, and creates no Link Monitor component or thread. This is an explicit MVP scope
reduction: bidirectional forwarding, mbuf ownership, partial-TX handling, cleanup, and the Cache Path take priority over
runtime link diagnostics. Any negative return from `rte_eth_link_get_nowait()` produces one warning containing the port
identity and DPDK error, then startup continues and the other port is still queried. Module 9 does not retry the query or
promote `-ENOTSUP`, `-ENODEV`, `-EINVAL`, or another query error to `StartFailed`. A successfully observed down state is
likewise never a startup gate.

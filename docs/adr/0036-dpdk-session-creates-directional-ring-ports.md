# DPDK Session Creates Directional Ring Ports

Status: accepted

For each `kind = "ring"` Device Source, `DpdkNativeSession` explicitly creates distinct ingress and egress `rte_ring`
objects and wraps them in an Ethernet device with `rte_eth_from_rings()`. It does not ask EAL to create a bare
`--vdev=net_ringX` device because that default topology uses the same ring for RX and TX and can feed a transmitted
packet back into Shinku's own receive path.

The ring-specific implementation ends at ethdev creation. Capability discovery, MTU and promiscuous setup, queue
configuration, `rte_eth_rx_burst()`/`rte_eth_tx_burst()` forwarding, Link State observation, and shutdown use the same
Session path as PCI ports. Session exclusively owns the ring-backed ethdevs and their rings and releases partial or
complete acquisition in reverse order exactly once.

Ring handles are not part of the production Backend interface or Config model. The mandatory in-process virtual-device
smoke receives an internal fixture that can enqueue mbufs into the client-side or service-side ingress ring and dequeue
them from the corresponding egress ring. This proves both forwarding directions through the real net_ring ethdev path
without claiming physical-PMD performance or exposing a second production packet-I/O interface.

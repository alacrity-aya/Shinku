# DPDK Config Binds Device Identity Rather Than Port ID

Status: accepted

The DPDK Config assigns the client-side and DNS-service-side roles to typed DPDK Device Sources, using stable PCI BDFs
or supported virtual-device identities. After EAL initialization, `DpdkNativeSession` resolves those identities to the
runtime Port IDs consumed by ethdev APIs. User-configured numeric Port IDs are rejected because their meaning depends on
EAL enumeration order and duplicates the device identity already required for controlled initialization. This
supersedes ADR-0017's decision to expose `dpdk.client_port` and `dpdk.server_port`; the two-port transparent topology
remains unchanged.

The TOML interface uses required nested tables rather than inline tables or a prefixed string protocol:

```toml
[dpdk]
memory_mode = "no_huge"

[dpdk.client]
kind = "ring"
name = "shinku-client"

[dpdk.service]
kind = "pci"
address = "0000:03:00.0"
```

Each side has `kind = "pci" | "ring"` and exactly one matching identity field. PCI requires `address` and forbids
`name`; ring requires `name` and forbids `address`. Missing side tables, unknown kinds, empty or contradictory identity,
duplicate client/service identity, and the old numeric Port ID keys are Config errors. The validated C++ representation
is `std::variant<PciDeviceSource, RingDeviceSource>` for each side; raw TOML, devargs, and runtime Port IDs remain private
to their owning adapters and Session implementation.

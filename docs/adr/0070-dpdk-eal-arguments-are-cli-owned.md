# DPDK EAL Arguments Are CLI-owned

Status: accepted

Module 9A passes every token after the Shinku CLI `--` separator directly to `rte_eal_init()`. Shinku prepends only the
required `argv[0]`; it does not synthesize lcore selection, memory mode, PCI allowlists, virtual devices, process type,
file prefix, Telemetry policy, or any other EAL option. An empty argument list is valid and selects DPDK defaults.

TOML retains `backend = "dpdk"` only as the Shinku Backend selector. There is no DPDK configuration object or required
`[dpdk]` table in this MVP. Obsolete `[dpdk]` fields are temporarily ignored without diagnostics; deciding their final
migration behavior is explicitly deferred in the Config Loader.

After EAL initialization, Shinku requires exactly two available ethdev ports and uses the fixed role mapping Port 0 as
client and Port 1 as service. Any other available-port count is `StartFailed`. The launch environment is responsible for
using native EAL options such as allowlists, blocklists, or vdev declarations to produce that exact port set and order.

The native DPDK boundary is split into object-oriented `DpdkEal`, `DpdkPacketPool`, and `DpdkPort` resources. They invoke
DPDK directly rather than routing each library function through a function-pointer table or a mixed Session façade. Unit
tests use the three narrow interfaces; the real `net_ring` smoke covers the production adapters. See ADR-0071.

This supersedes ADR-0019, ADR-0021, ADR-0034's automatic lcore-argument generation, ADR-0036, ADR-0038, ADR-0039,
ADR-0040, and ADR-0041 wherever those records require Shinku-generated EAL arguments or TOML Device Sources. Their
other lifecycle, one-lcore, and deployment constraints remain applicable.

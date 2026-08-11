# DPDK Memory Mode Is Explicit

Status: accepted

The DPDK Backend requires a typed `dpdk.memory_mode` Config value of `hugepages` or `no_huge`. Config Loader validates
the value and Effective Config retains it. Session converts it into private EAL arguments and performs one initialization
attempt. A failure does not cause Shinku to retry with the other mode because EAL reinitialization is not a supported
lifecycle and an implicit fallback would make deployed memory and DMA behavior irreproducible.

Mandatory ring/ring functional evidence uses `no_huge` so it runs without host Hugepage provisioning. Physical and
mixed deployment examples use and recommend `hugepages`; actual Hugepage availability, driver compatibility, and EAL
initialization are startup checks rather than Config Loader checks. Supporting `no_huge` in Config does not claim that
every physical PMD or IOVA environment can operate in that mode.

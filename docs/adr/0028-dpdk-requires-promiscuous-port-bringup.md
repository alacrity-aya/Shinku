# DPDK Requires Promiscuous Port Bring-up

Status: accepted

Module 9 requires every configured port to enter promiscuous mode through the common DPDK ethdev API after
`rte_eth_dev_start()`. The Backend treats a failed or unsupported `rte_eth_promiscuous_enable()` call as `StartFailed`,
including for the mandatory `net_ring` virtual-device smoke. The setting is part of transparent port bring-up and is
released during reverse cleanup when the PMD exposes a corresponding operation.

This deliberately chooses an API-level capability contract instead of inferring that a virtual Device Source happens to
accept all frames. A future Device Source may add a separately justified semantic capability adapter, but Module 9's
PCI and virtual evidence must exercise the same explicit promiscuous bring-up rule.

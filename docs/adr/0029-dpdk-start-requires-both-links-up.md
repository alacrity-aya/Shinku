# DPDK Start Requires Both Links Up

Status: superseded by ADR-0030

After both ports have started and entered promiscuous mode, Module 9 immediately queries each port's link state. Any
query error or link-down result fails Backend start. The rule applies equally to PCI and `net_ring`, and the mandatory
virtual smoke must demonstrate link-up through the same ethdev operation.

The Backend does not wait for physical negotiation, retry the query, provide a grace period, or expose a link-startup
timeout. This makes successful startup evidence that both transparent sides were immediately available, at the cost of
requiring deployment orchestration to establish physical links before starting Shinku.

# DPDK Cooperative Scheduler Is Client-first

Status: accepted

Every Module 9 DPDK Poll Quantum invokes its bounded tasks in one fixed order:

1. Client Packet Path.
2. Service Packet Path.
3. Cache Cleanup, when due or continuing bounded work.
4. Pending Cleanup, when due or continuing bounded work.

Client-first is a Query Correlation rule as well as a scheduling preference. An eligible Query can publish or refresh
its Pending record before a matching Response consumed from the service side later in the same quantum attempts to
claim it. Both Packet Paths always receive their one-burst opportunity before maintenance work.

Each maintenance task performs at most one bounded batch in a quantum. A `more_work` result preserves continuation for
the next quantum but does not drain the table immediately, rotate task order, or move cleanup ahead of packet work. All
four tasks have strict bounds and `BackendRunner` immediately begins the next Poll Quantum, so fixed order provides
continued progress without a round-robin starting cursor.

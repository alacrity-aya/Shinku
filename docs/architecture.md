# Shinku Module Architecture

This document describes how runtime modules are connected, which data each module owns, and how packets and control signals flow through the system.

## 1. Module graph

```text
                    +-----------------------------+
                    |         CLI Layer           |
                    | src/cli/main.c, config.c    |
                    +-------------+---------------+
                                  |
                                  v
                    +-----------------------------+
                    |       Loader Runtime        |
                    | src/core/loader.c           |
                    | - attach XDP/TC programs    |
                    | - map/ring setup + mmap     |
                    | - cleanup thread lifecycle  |
                    +-------------+---------------+
                                  |
               +------------------+------------------+
               |                                     |
               v                                     v
   +--------------------------+          +--------------------------+
   |       BPF Dataplane      |          |    Userspace Pipeline    |
   | src/bpf/cache.bpf.c      |          | src/core/dns_parser.c    |
   | - XDP query fast path    |          | - response validation    |
   | - TC response capture    |          | - flatten/store to arena |
   +-------------+------------+          +-------------+------------+
                 |                                     |
                 +------------------+------------------+
                                    v
                    +-----------------------------+
                    | Shared State + Ops Loops    |
                    | - cache_map (BPF hash map)  |
                    | - arena cache_entries[]     |
                    | - rb_pkt ring buffer        |
                    +-----------------------------+
```

## 2. Data ownership by module

- `src/bpf/cache.bpf.c`
  - Owns packet fast-path logic.
  - Reads from `cache_map` and `cache_entries` arena.
  - Emits captured DNS responses to `rb_pkt` for userspace.

- `src/core/dns_parser.c`
  - Owns DNS response admissibility policy.
  - Writes cache payloads into `cache_entries` and metadata into `cache_map`.
  - Maintains slot reuse safety via `slot_owners` and generation counters.

- `src/core/loader.c`
  - Owns BPF object lifecycle (load/attach/detach), map FD wiring, arena mmap, ring-buffer polling, cleanup thread orchestration.

## 3. End-to-end request and response flow

### Query path (client -> XDP)
1. XDP parses Ethernet/VLAN/IPv4/UDP/DNS query.
2. XDP computes cache key from `name_hash + qtype + qclass + ECS partition`.
3. On hit and non-expired entry: XDP copies cached DNS payload from arena, patches TxID, rewrites headers, returns `XDP_TX`.
4. On miss/expired/invalid entry: XDP returns `XDP_PASS` and query reaches upstream resolver.

### Response path (upstream -> TC -> userspace)
1. TC captures UDP/53 responses and writes payload into `rb_pkt`.
2. Userspace parser validates packet policy (question shape, TTL, supported RRs, negative-cache rules, ECS validity).
3. Parser normalizes/stores DNS payload into arena and updates `cache_map` key/value.
4. Future matching queries are served at XDP layer.

## 4. ECS-specific anti-pollution design

Shinku prevents ECS cache pollution by partitioning cache keys with ECS fields:

- `cache_key.ecs_addr_v4` (masked subnet address)
- `cache_key.ecs_prefix` (source prefix length)
- `cache_key.ecs_family` (IPv4=1, absent=0)

Policy behavior:
- Query with ECS and response with matching ECS subnet is cached in that subnet partition.
- Same subnet queries reuse cached response.
- Different subnet queries do not hit that entry.
- ECS `/0` remains globally reusable by design.

This ensures ECS-targeted answers are never served across unrelated networks.

## 5. Concurrency and safety invariants

- Arena payload consistency: writer seqlock (`cache_entry.seq`) + reader retry check.
- Slot-reuse detection: `cache_entry.gen` must equal `cache_value.gen`.
- Eviction correctness: `slot_owners[idx]` reverse mapping removes stale key on slot recycle.
- TTL safety: XDP enforces `expire_ts`; userspace cleanup removes expired entries asynchronously.

## 6. Runtime control loops

- Ring-buffer poll loop: drains `rb_pkt` and feeds parser.
- Cleanup thread: periodically calls `dns_parser_cleanup_expired_entries`.
- Degraded-mode updates: driven by startup retry state, cleanup outcomes, poll errors, cache-map update failures.

## 7. Current scope boundaries

- IPv4 DNS hot path is in scope.
- IPv6 query/response caching is intentionally ignored by current policy.
- DNS-over-TCP and large-response strategies remain future roadmap items.

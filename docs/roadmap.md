# DNS Cache Roadmap — Next Steps

This document outlines the planned trajectory for the eBPF DNS cache project, categorized by priority and impact. The goals focus on moving from a functional prototype to a production-ready, high-performance caching layer.

## Phase 1: Critical Improvements
High impact items required for stable production deployments.

### 1.1 Arena Memory Reclamation
*   **Current State**: The system uses a simple bump allocator (`next_entry_idx++`) for the arena memory map. It never frees or reuses entries, meaning the cache stops accepting new records once it reaches the 16,384 entry limit.
*   **Proposed Solution**: Implement a ring buffer allocator. When `next_entry_idx` reaches the maximum capacity, it wraps back to zero, overwriting the oldest entries.
*   **Impact**: This is essential for long-running instances. In a DNS context, older entries are naturally less likely to be valid or frequently accessed, making them ideal candidates for overwrite when the arena is full.

### 1.2 Cache Eviction Policy
*   **Current State**: Expired entries remain in the `cache_map` until a hash collision occurs or the map fills up. There's no proactive cleanup of stale data.
*   **Proposed Solution**: Develop a userspace timer component that periodically scans the `cache_map` using `bpf_map_get_next_key` and `bpf_map_lookup_elem`. It will delete any entry where the expiration timestamp is older than the current time. A scan interval of 30 to 60 seconds is recommended.
*   **Impact**: Prevents stale data from polluting the hash map and preserves arena slots for fresh queries.

### 1.3 IPv6 Support
*   **Current State**: The XDP program currently only parses `ETH_P_IP` (IPv4). All IPv6 traffic passes through the hook without being inspected or cached.
*   **Proposed Solution**: Add support for `ETH_P_IPV6` (0x86DD). This requires handling the 40-byte fixed IPv6 header and potentially skipping extension headers. Crucially, UDP checksum calculation must be implemented for IPv6 responses, as it's mandatory and requires a pseudo-header containing 128-bit source and destination addresses.
*   **Impact**: Modern dual-stack and IPv6-only networks are increasingly common. Without this support, a significant portion of DNS traffic bypasses the cache entirely.

### 1.4 Record Type Expansion (CNAME/MX/TXT)
*   **Current State**: Only A and AAAA records are cached. Responses containing other types like CNAME chains, MX, or TXT records are currently ignored.
*   **Proposed Solution**: Enhance the RDATA parsing logic. CNAME records are the highest priority as they often precede A/AAAA records in recursive lookups. Parsing CNAMEs requires handling DNS name compression pointers to flatten the name before storing it in the arena.
*   **Impact**: Supporting CNAME chains will significantly increase the cache hit rate for major web services that rely on traffic management via aliases.

## Phase 2: Performance Optimizations
Enhancements to maximize throughput and minimize latency.

### 2.1 Native XDP on Physical Hardware
*   **Current State**: Benchmarking has been performed on `veth` pairs using generic XDP mode, where the kernel allocates an `sk_buff` before XDP processing.
*   **Proposed Solution**: Test and benchmark the system on physical NICs (e.g., Intel i40e, ixgbe, or Mellanox mlx5) that support native XDP.
*   **Impact**: Moving to native XDP can yield a 3x to 10x performance gain by processing packets directly in the driver before any expensive kernel memory allocation occurs.

### 2.2 XDP Multi-Buffer Support
*   **Current State**: The current implementation assumes DNS packets fit within a single buffer.
*   **Proposed Solution**: Implement support for `xdp_buff` fragments (multi-buffer XDP).
*   **Impact**: While standard 512-byte UDP DNS queries fit in a single frame, EDNS0 allows for payloads up to 4096 bytes. Multi-buffer support ensures the cache can handle large DNSSEC-signed responses or jumbo frames.

### 2.3 Batch Ring Buffer Processing
*   **Current State**: The userspace daemon processes ring buffer events one by one via `ring_buffer__poll`.
*   **Proposed Solution**: Switch to `ring_buffer__consume` within a tight loop or implement a batch processing strategy to handle multiple events per syscall.
*   **Impact**: Reduces the overhead of transitions between kernel and userspace when the system is under heavy load and many packets are being captured for caching.

### 2.4 BPF Map Tuning
*   **Current State**: The system uses `BPF_MAP_TYPE_HASH` for the main `cache_map`.
*   **Proposed Solution**: Evaluate `BPF_MAP_TYPE_LRU_HASH`.
*   **Impact**: An LRU map automatically evicts the least recently used entries when it reaches capacity. This could simplify or even eliminate the need for manual eviction logic, though it comes with a slight increase in per-lookup overhead that needs to be measured.

## Phase 3: Feature Additions
Functional enhancements for broader utility.

### 3.1 Negative Caching
*   **Current State**: Only successful resolutions are cached. NXDOMAIN or SERVFAIL responses are ignored.
*   **Proposed Solution**: Store negative responses (NXDOMAIN) using the TTL found in the Authority section's SOA record.
*   **Impact**: Reduces load on upstream resolvers caused by typos, bots, or ad-blocking lists that frequently query non-existent domains.

### 3.2 DNS-over-TCP Fallback
*   **Current State**: The cache only monitors UDP port 53.
*   **Proposed Solution**: Extend the TC program to capture TCP port 53 traffic and implement basic TCP session tracking in userspace to cache responses that were truncated (TC=1) over UDP.
*   **Impact**: Ensures consistency and coverage for large responses that force a switch to TCP.

### 3.3 Subnet-Specific Caching (ECS)
*   **Current State**: Only global responses (scope-zero) are cached.
*   **Proposed Solution**: Incorporate EDNS Client Subnet (ECS) info into the `cache_key`.
*   **Impact**: Allows the cache to serve geographically relevant answers to different client subnets while maintaining correctness for CDN-backed domains.

### 3.4 Metrics and Observability
*   **Current State**: There is limited visibility into internal cache performance.
*   **Proposed Solution**: Add per-CPU BPF counters for cache hits, misses, expired hits, and packet actions. Expose these through a Prometheus-compatible `/metrics` endpoint.
*   **Impact**: Critical for operational monitoring, capacity planning, and identifying bottlenecks in production.

### 3.5 Graceful Program Updates
*   **Current State**: Restarting the tool may lead to temporary traffic disruption.
*   **Proposed Solution**: Use `bpf_link__update_program()` to atomically swap XDP and TC programs without dropping the attached link.
*   **Impact**: Enables seamless updates to the caching logic while the system is under load.

## Phase 4: Long-Term Research
Exploratory work for extreme scale and complexity.

### 4.1 AF_XDP Hybrid Architecture
*   **Description**: Redirect specific DNS traffic to a specialized userspace responder using AF_XDP zero-copy sockets.
*   **Reasoning**: For environments with extreme throughput requirements where XDP_TX latency is still a bottleneck, moving response generation to a dedicated userspace application using DPDK or AF_XDP can offer even higher performance.

### 4.2 Inline DNSSEC Validation
*   **Description**: Perform cryptographic validation of DNSSEC signatures within the userspace caching daemon.
*   **Reasoning**: Currently, the cache trusts the upstream resolver's AD bit. Local validation would provide an additional layer of security, though it adds significant complexity due to the need for RSA/ECDSA verification.

### 4.3 Distributed Cache State
*   **Description**: Share cache entries between multiple nodes in a cluster.
*   **Reasoning**: Investigating BPF map pinning to `bpffs` for local sharing or a lightweight gossip protocol for network-wide coordination would allow for a unified cache across a fleet of load balancers.

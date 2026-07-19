# Tested Features

This document lists all features covered by the test suite.

## Unit Tests (`tests/unit/`)

### DNS Hash (`hash/dns_hash_test.c`)

- **XDP Hash - Basic Names**: FNV-1a hashing for DNS names without compression
- **XDP Hash - Compression Pointer Rejection**: Rejects compression pointers in XDP path
- **XDP Hash - Case Normalization**: Case-insensitive hashing (upper/lower produce same hash)
- **XDP Hash - Bounds Checking**: Rejects truncated packets with invalid label lengths
- **User Space Hash - Compression Support**: Resolves compression pointers for userspace hashing
- **Flatten Name - Decompression**: Correctly flattens compressed DNS names
- **Consistency - XDP vs User Space**: Hash values match between XDP and userspace for flat packets
- **Edge Cases**: Root domain, single label, NULL dest for length measurement

### DNS Parser (`parser/dns_parser_test.c`)

**Positive Tests:**
- Simple A record parsing and caching
- AAAA query path ignored by policy (not cached)
- Multiple A records in single response
- Minimum TTL selection (picks lowest TTL among multiple answers)
- Cache key construction correctness
- Sequential store operations

**Negative Tests:**
- Reject query packets (QR=0)
- Cache truncated responses (TC=1) as UDP fallback hints for repeated UDP clients
- Reject zero answer count
- Reject QDCOUNT != 1
- Reject packets shorter than DNS header (12 bytes)
- Reject TTL=0 records
- Reject unsupported record types (MX, etc.)

**Negative Caching (NXDOMAIN/NODATA):**
- Cache NXDOMAIN responses when an SOA record is present in authority section
- Cache NODATA responses (NOERROR + ANCOUNT=0) when an SOA record is present
- Reject negative caching when SOA is missing (NXDOMAIN and NODATA)
- Use negative TTL policy based on `min(SOA TTL, SOA.MINIMUM)` with policy bounds

**CNAME Handling:**
- CNAME with terminal A record (valid chain)
- CNAME chain with terminal A record (multi-level)
- Reject CNAME-only response without terminal record
- Reject CNAME+AAAA-only terminal for A query under IPv6-ignore policy

**ECS Handling:**
- Accept ECS scope=0 responses and cache as global (`/0`) when key partition is zeroed
- Cache ECS scope>0 responses with ECS subnet-partitioned key
- Reject invalid ECS family/prefix in response OPT records
- ECS test group is profile-gated and runs only when build/profile enables ECS

**Edge Cases:**
- Oversized packet handling (>512 bytes flat length)
- Arena wraparound on full cache
- NULL context handling (graceful degradation)

### Cache Store (`cache/cache_store_test.c`)

- **Seqlock Write Protocol**: Verifies seq increments (0 -> 1 -> 2) bracket writes
- **Generation Counter Consistency**: cache_entry.gen matches cache_value.gen
- **Eviction on Wraparound**: Old entries deleted from cache_map when slot recycled
- **Seqlock Torn Read Detection**: Concurrent readers detect write-in-progress via odd seq
- **TTL Cleanup**: Expired entries removed from cache_map and slot_owners cleared
- **Slot Owners Tracking**: Reverse mapping (slot_idx -> cache_key) maintained correctly

### Ring Buffer Allocator (`allocator/ring_buffer_test.c`)

- Sequential allocation returns correct indices
- Wrap-around at max_entries boundary
- Multiple wrap-arounds with correct modulo
- Index modulo with near-UINT32_MAX values
- Boundary conditions (last slot before wrap)
- Concurrent allocation (multi-threaded, atomic fetch_add)
- Single entry ring (always returns 0)
- Large ring buffer (1000+ entries)
- Power-of-two sizes
- Prime sizes

### c-ares DNS Expand (`cares/cares_expand_test.c`)

- Simple compression pointer expansion
- Nested compression (CNAME chain with multiple pointers)
- Compression pointer to question name
- Compression pointer in RDATA

### BPF Arena List (`arena/arena_list_test.c`)

> Requires root privileges

- Arena list add elements via BPF program
- Arena list delete elements via BPF program
- List sum computation in userspace from arena memory
- Correct element count after operations

### BPF Arena Hash Table (`arena/arena_htab_test.c`)

> Requires root privileges

- Hash table insertion (100,000 elements)
- Hash table lookup and verification
- Element count verification
- Array verification in arena memory

### DNS Benchmark (`bench/dns_bench.c`)

> Manual benchmark, not a test

- Hash throughput measurement
- Parser latency measurement
- Cache store throughput measurement
- Multi-iteration warmup and timing

---

## Integration Tests (`tests/integration/`)

### DNS Cache Integration (`test_dns_cache.py`)

- Full system test with network namespaces
- DNS query/response flow through XDP
- Cache hit/miss behavior
- CNAME cache hit behavior (CNAME+A and CNAME chain + terminal A)
- CNAME-only A query non-cache behavior
- AAAA query non-cache behavior under IPv6-ignore policy
- Negative caching for NXDOMAIN (with SOA)
- Negative caching for NODATA (with SOA)
- No negative caching when SOA is absent
- ECS same-subnet cache hit
- ECS different-subnet non-reuse
- ECS /0 global reuse behavior

---

## Test Summary

| Category | Test File | Tests | Root Required |
|----------|-----------|-------|---------------|
| DNS Hash | `hash/dns_hash_test.c` | 8 suites | No |
| DNS Parser | `parser/dns_parser_test.c` | 20+ tests | No* |
| Cache Store | `cache/cache_store_test.c` | 6 tests | No* |
| Ring Buffer | `allocator/ring_buffer_test.c` | 10 suites | No |
| c-ares Expand | `cares/cares_expand_test.c` | 2 tests | No |
| Arena List | `arena/arena_list_test.c` | 1 test | Yes |
| Arena Hash Table | `arena/arena_htab_test.c` | 1 test | Yes |
| DNS Benchmark | `bench/dns_bench.c` | - | No* |

\* Some tests degrade gracefully without BPF map access (root), testing arena-only logic.

---

## Running Tests

```bash
# Run all unit tests
meson test -C build

# Run specific test
meson test -C build "DNS Parser Test"

# Run BPF arena tests (requires root)
sudo meson test -C build "Arena List Test"
sudo meson test -C build "Arena Hash Table Test"

# Run integration tests (requires root)
sudo python3 tests/integration/test_dns_cache.py
```

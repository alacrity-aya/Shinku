# eBPF DNS Cache MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 实现 eBPF DNS 缓存 MVP，支持 A 记录缓存、XDP 快速路径反射响应。

**Architecture:** 用户态控制面通过 Ring Buffer 接收 DNS 响应，规范化后存储到 BPF Arena；XDP 程序查找缓存，热修补 Transaction ID 和校验和后通过 XDP_TX 反射响应。

**Tech Stack:** eBPF (XDP/TC), BPF Arena (Linux 6.9+), libbpf, Ring Buffer, FNV-1a Hash

---

## Phase 3: BPF Arena 集成

---

### Task 1: 定义数据结构 (types.h)

**Files:**
- Modify: `src/common/types.h`

**Step 1: 添加 cache_value 结构体**

在 `struct dns_event` 之后添加：

```c
// Cache Value - stored in cache_map
struct cache_value {
    __u64 arena_offset;  // Offset in BPF Arena
    __u64 expire_ts;     // Expiration timestamp (nanoseconds)
    __u16 pkt_len;       // Actual DNS packet length (<= 512B)
    __u8  scope;         // ECS Scope (0=global, >0=subnet-specific)
    __u8  _pad[5];       // Alignment padding
};  // 24 bytes
```

**Step 2: 添加 Arena 常量**

在 `src/common/constants.h` 中添加：

```c
// BPF Arena
#define ARENA_ENTRY_SIZE 512       // Max DNS UDP packet size
#define ARENA_DEFAULT_SIZE (4 * 1024 * 1024)  // 4MB default
#define ARENA_ALLOC_FAILED ((__u64)-1)
```

**Step 3: 验证编译**

Run: `meson compile -C build`
Expected: 编译成功，无错误

**Step 4: Commit**

```bash
git add src/common/types.h src/common/constants.h
git commit -m "feat(types): add cache_value and arena constants"
```

---

### Task 2: 定义 BPF Maps (cache.bpf.c)

**Files:**
- Modify: `src/bpf/cache.bpf.c`

**Step 1: 添加 cache_map 定义**

在 `rb_pkt` map 之后添加：

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct cache_key);
    __type(value, struct cache_value);
} cache_map SEC(".maps");
```

**Step 2: 添加 Arena map 定义**

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(max_entries, ARENA_DEFAULT_SIZE);
    __uint(map_flags, 0);
} arena SEC(".maps");
```

**Step 3: 验证 BPF 编译**

Run: `meson compile -C build`
Expected: 编译成功，BPF 程序通过验证器检查（如有警告可忽略）

**Step 4: Commit**

```bash
git add src/bpf/cache.bpf.c
git commit -m "feat(bpf): add cache_map and arena map definitions"
```

---

### Task 3: 创建 Arena 分配器头文件

**Files:**
- Create: `src/user/arena.h`

**Step 1: 创建头文件**

```c
#pragma once

#include <stdint.h>
#include <stddef.h>

#define ARENA_ENTRY_SIZE 512
#define ARENA_ALLOC_FAILED ((uint64_t)-1)

struct arena_allocator {
    uint64_t next_offset;   // Bump pointer
    uint64_t capacity;      // Total capacity in bytes
    uint32_t entry_count;   // Number of allocated entries
    uint32_t max_entries;   // Maximum entries
};

// Initialize allocator
void arena_init(struct arena_allocator *alloc, uint64_t capacity);

// Allocate one entry (512B aligned)
// Returns offset in arena, or ARENA_ALLOC_FAILED if full
uint64_t arena_alloc(struct arena_allocator *alloc);

// Free an entry (add to freelist - future enhancement)
void arena_free(struct arena_allocator *alloc, uint64_t offset);

// Get pointer to arena data
void *arena_ptr(void *arena_base, uint64_t offset);
```

**Step 2: Commit**

```bash
git add src/user/arena.h
git commit -m "feat(arena): add arena allocator header"
```

---

### Task 4: 实现 Arena 分配器

**Files:**
- Create: `src/user/arena.c`

**Step 1: 创建实现文件**

```c
#include "arena.h"
#include <string.h>

void arena_init(struct arena_allocator *alloc, uint64_t capacity) {
    memset(alloc, 0, sizeof(*alloc));
    alloc->capacity = capacity;
    alloc->max_entries = capacity / ARENA_ENTRY_SIZE;
}

uint64_t arena_alloc(struct arena_allocator *alloc) {
    // Bump allocation (MVP: no freelist)
    if (alloc->next_offset + ARENA_ENTRY_SIZE > alloc->capacity) {
        return ARENA_ALLOC_FAILED;
    }
    
    uint64_t offset = alloc->next_offset;
    alloc->next_offset += ARENA_ENTRY_SIZE;
    alloc->entry_count++;
    
    return offset;
}

void arena_free(struct arena_allocator *alloc, uint64_t offset) {
    // MVP: no-op (TTL expiration only)
    // Future: add to freelist for reuse
    (void)alloc;
    (void)offset;
}

void *arena_ptr(void *arena_base, uint64_t offset) {
    return (uint8_t *)arena_base + offset;
}
```

**Step 2: 更新 meson.build**

在 `src/user/` 的源文件列表中添加 `arena.c`。

**Step 3: 验证编译**

Run: `meson compile -C build`
Expected: 编译成功

**Step 4: Commit**

```bash
git add src/user/arena.c meson.build
git commit -m "feat(arena): implement bump allocator for BPF arena"
```

---

### Task 5: 完善 ECS Scope 检查 (parser.c)

**Files:**
- Modify: `src/user/parser.c`

**Step 1: 添加 ECS 检查函数**

在文件顶部 `#include` 之后添加：

```c
// EDNS0 Option Codes
#define EDNS0_OPT_CODE_ECS 8  // EDNS Client Subnet

// Parse OPT RR and check ECS scope
// Returns: 0=global (no ECS or scope=0), >0=subnet-specific, -1=parse error
static int check_ecs_scope(const uint8_t *pkt, int offset, int max_len, int rdlen) {
    int end = offset + rdlen;
    
    while (offset + 4 <= end && offset + 4 <= max_len) {
        uint16_t opt_code = read_u16(pkt + offset);
        uint16_t opt_len = read_u16(pkt + offset + 2);
        offset += 4;
        
        if (offset + opt_len > end || offset + opt_len > max_len) {
            return -1;  // Parse error
        }
        
        if (opt_code == EDNS0_OPT_CODE_ECS && opt_len >= 4) {
            // ECS format: FAMILY(2) SOURCE PREFIX(1) SCOPE PREFIX(1) ADDRESS...
            uint8_t scope = pkt[offset + 3];
            return scope;  // Return scope value
        }
        
        offset += opt_len;
    }
    
    return 0;  // No ECS found, treat as global
}
```

**Step 2: 修改 handle_packet 函数**

在 `handle_packet` 函数中，找到 `// 3.3 Flatten Answers` 循环结束后，添加 ECS 检查：

```c
    // After flattening answers, check for ECS in Additional Section
    // Skip Authority Section (nscount)
    for (int i = 0; i < nscount && read_offset < pkt_len; i++) {
        int skip_len = calculate_hash_strict(pkt_data, read_offset, pkt_len, &name_hash);
        if (skip_len < 0) return 0;
        read_offset += skip_len;
        if (read_offset + 10 > pkt_len) return 0;
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);
        read_offset += 10 + rdlen;
    }
    
    // Check Additional Section for ECS
    uint8_t ecs_scope = 0;
    for (int i = 0; i < ntohs(dns->arcount) && read_offset < pkt_len; i++) {
        int skip_len = calculate_hash_strict(pkt_data, read_offset, pkt_len, &name_hash);
        if (skip_len < 0) return 0;
        read_offset += skip_len;
        if (read_offset + 10 > pkt_len) return 0;
        uint16_t rtype = read_u16(pkt_data + read_offset);
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);
        read_offset += 10;
        
        if (rtype == 41) {  // OPT RR
            int scope = check_ecs_scope(pkt_data, read_offset, pkt_len, rdlen);
            if (scope < 0) return 0;
            if (scope > 0) {
                printf("[Cache] Skip: ECS Scope=%d (subnet-specific)\n", scope);
                return 0;  // Don't cache subnet-specific responses
            }
            ecs_scope = (uint8_t)scope;
        }
        read_offset += rdlen;
    }
```

**Step 3: 更新 cache_value 结构**

在 `handle_packet` 末尾，更新存储逻辑（暂时保留注释状态，等 Task 6 完成）：

```c
    // Store to cache (enabled after Task 6)
    // struct cache_value val = {
    //     .arena_offset = arena_offset,
    //     .expire_ts = expire_ts,
    //     .pkt_len = flat_offset,
    //     .scope = ecs_scope,
    // };
```

**Step 4: 验证编译**

Run: `meson compile -C build`
Expected: 编译成功

**Step 5: Commit**

```bash
git add src/user/parser.c
git commit -m "feat(parser): add ECS scope check for cache eligibility"
```

---

### Task 6: 集成 Ring Buffer 消费与缓存更新

**Files:**
- Modify: `src/user/main.c`
- Modify: `src/user/parser.h`

**Step 1: 添加 arena.h 和 bpf 头文件引用**

在 `main.c` 顶部添加：

```c
#include "arena.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
```

**Step 2: 添加全局变量**

```c
static struct arena_allocator g_arena;
static int cache_map_fd = -1;
static void *arena_base = NULL;
```

**Step 3: 实现 Ring Buffer 回调**

修改或创建 `handle_event` 函数：

```c
static int handle_event(void *ctx, void *data, size_t len) {
    return handle_packet(ctx, data, len);
}
```

**Step 4: 添加缓存存储函数**

```c
static int store_to_cache(
    struct cache_key *key,
    uint8_t *flat_buf,
    int flat_len,
    uint32_t min_ttl,
    uint8_t scope
) {
    if (flat_len > ARENA_ENTRY_SIZE) {
        return -1;
    }
    
    // Allocate arena slot
    uint64_t offset = arena_alloc(&g_arena);
    if (offset == ARENA_ALLOC_FAILED) {
        printf("[Cache] Arena full, cannot store\n");
        return -1;
    }
    
    // Write to arena
    void *slot = arena_ptr(arena_base, offset);
    memcpy(slot, flat_buf, flat_len);
    
    // Calculate expiration time
    uint64_t expire_ts = time(NULL) + min_ttl;
    expire_ts *= 1000000000ULL;  // Convert to nanoseconds
    
    // Update cache_map
    struct cache_value val = {
        .arena_offset = offset,
        .expire_ts = expire_ts,
        .pkt_len = (uint16_t)flat_len,
        .scope = scope,
    };
    
    int err = bpf_map_update_elem(cache_map_fd, key, &val, BPF_ANY);
    if (err) {
        printf("[Cache] Failed to update map: %d\n", err);
        arena_free(&g_arena, offset);
        return -1;
    }
    
    printf("[Cache] Stored: Hash=0x%x Size=%d TTL=%u\n", 
           key->name_hash, flat_len, min_ttl);
    return 0;
}
```

**Step 5: 修改 main 函数初始化**

在 BPF 程序加载后，添加：

```c
    // Initialize arena allocator
    arena_init(&g_arena, ARENA_DEFAULT_SIZE);
    
    // Get cache_map fd
    cache_map_fd = bpf_map__fd(skel->maps.cache_map);
    if (cache_map_fd < 0) {
        fprintf(stderr, "Failed to get cache_map fd\n");
        return 1;
    }
    
    // Get arena base pointer
    arena_base = skel->maps.arena->data;
    if (!arena_base) {
        fprintf(stderr, "Failed to get arena base\n");
        return 1;
    }
```

**Step 6: 验证编译**

Run: `meson compile -C build`
Expected: 编译成功

**Step 7: Commit**

```bash
git add src/user/main.c src/user/parser.h
git commit -m "feat(main): integrate arena storage and cache_map update"
```

---

### Task 7: 添加命令行参数支持 Arena 大小

**Files:**
- Modify: `src/user/config.c`
- Modify: `src/user/config.h`

**Step 1: 添加配置字段**

在 `struct config` 中添加：

```c
    uint64_t arena_size;  // Arena size in bytes
```

**Step 2: 添加命令行参数解析**

在 `parse_args` 函数中添加：

```c
    { "arena-size", required_argument, NULL, 'a' },
```

在 switch case 中添加：

```c
        case 'a':
            config->arena_size = strtoull(optarg, NULL, 0);
            break;
```

**Step 3: 设置默认值**

在 `parse_args` 开头添加默认值：

```c
    config->arena_size = ARENA_DEFAULT_SIZE;
```

**Step 4: 验证编译**

Run: `meson compile -C build`
Expected: 编译成功

**Step 5: Commit**

```bash
git add src/user/config.c src/user/config.h
git commit -m "feat(config): add --arena-size CLI option"
```

---

## Phase 4: XDP 快速路径

---

### Task 8: 实现 XDP 缓存查找

**Files:**
- Modify: `src/bpf/cache.bpf.c`

**Step 1: 添加缓存查找逻辑**

在 `xdp_rx` 函数中，找到 `// TODO: bpf_map_lookup_elem` 注释，替换为：

```c
    // Lookup cache
    struct cache_value *val = bpf_map_lookup_elem(&cache_map, &key);
    if (!val) {
        bpf_debug("[XDP] Cache miss: Hash=0x%x", key.name_hash);
        return XDP_PASS;
    }
    
    // Check expiration
    __u64 now = bpf_ktime_get_ns();
    if (now >= val->expire_ts) {
        bpf_debug("[XDP] Cache expired: Hash=0x%x", key.name_hash);
        return XDP_PASS;
    }
    
    bpf_info("[XDP] Cache hit: Hash=0x%x Offset=%lu", key.name_hash, val->arena_offset);
```

**Step 2: 验证 BPF 编译**

Run: `meson compile -C build`
Expected: 编译成功

**Step 3: Commit**

```bash
git add src/bpf/cache.bpf.c
git commit -m "feat(xdp): implement cache lookup in fast path"
```

---

### Task 9: 实现增量校验和更新

**Files:**
- Modify: `src/bpf/cache.bpf.c`

**Step 1: 添加增量校验和函数**

在文件顶部 helper 函数之后添加：

```c
// Incremental checksum update
static __always_inline void update_checksum_incremental(
    __be16 *checksum, __be16 old_val, __be16 new_val
) {
    __u32 sum = (~bpf_ntohs(*checksum)) & 0xFFFF;
    sum += (~bpf_ntohs(old_val)) & 0xFFFF;
    sum += bpf_ntohs(new_val);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    *checksum = bpf_htons(~sum & 0xFFFF);
}
```

**Step 2: Commit**

```bash
git add src/bpf/cache.bpf.c
git commit -m "feat(xdp): add incremental checksum update helper"
```

---

### Task 10: 实现热修补与 XDP_TX

**Files:**
- Modify: `src/bpf/cache.bpf.c`

**Step 1: 添加热修补逻辑**

在缓存命中后添加：

```c
    // Get Arena data pointer
    void *arena_data = bpf_arena_get_data(&arena, val->arena_offset, val->pkt_len);
    if (!arena_data) {
        bpf_warn("[XDP] Arena access failed");
        return XDP_PASS;
    }
    
    // Hot-patch packet:
    // 1. Swap Ethernet MAC addresses
    struct ethhdr *eth = data;
    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);
    
    // 2. Swap IP addresses
    struct iphdr *ip = (void *)(eth + 1);
    __u32 tmp_ip = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp_ip;
    
    // 3. Swap UDP ports
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    __u16 tmp_port = udp->dest;
    udp->dest = udp->source;
    udp->source = tmp_port;
    
    // 4. Copy DNS response from arena to packet
    void *dns_payload = (void *)(udp + 1);
    if ((void *)dns_payload + val->pkt_len > data_end) {
        bpf_warn("[XDP] Packet too small for DNS response");
        return XDP_PASS;
    }
    
    __be16 old_id = dns->id;
    __builtin_memcpy(dns_payload, arena_data, val->pkt_len);
    
    // 5. Update Transaction ID in response
    struct dns_hdr *resp_dns = dns_payload;
    resp_dns->id = old_id;  // Keep original query ID
    
    // 6. Update checksums
    // Note: For simplicity, we recalculate. Incremental is future optimization.
    // IP checksum
    ip->check = 0;
    // (Full recalculation would require helper - simplified for MVP)
    
    // UDP checksum (can be 0 for IPv4 UDP)
    udp->check = 0;
    
    bpf_info("[XDP] Reflecting response: ID=0x%04x", bpf_ntohs(old_id));
    
    // 7. Adjust packet size
    __u32 new_pkt_len = ((void *)dns_payload - data) + val->pkt_len;
    if (bpf_xdp_adjust_tail(ctx, new_pkt_len - (data_end - data))) {
        bpf_warn("[XDP] Failed to adjust packet size");
        return XDP_PASS;
    }
    
    return XDP_TX;
```

**Step 2: 验证 BPF 编译**

Run: `meson compile -C build`
Expected: 编译成功（可能有验证器警告，需要迭代优化）

**Step 3: Commit**

```bash
git add src/bpf/cache.bpf.c
git commit -m "feat(xdp): implement hot-patch and XDP_TX response reflection"
```

---

### Task 11: 集成测试

**Files:**
- Test: 使用 `test/sender.py` 和 `test/topology.py`

**Step 1: 启动测试拓扑**

Run: `just net-up`
Expected: 网络命名空间创建成功

**Step 2: 运行 DNS 缓存程序**

Run: `sudo ./build/dns-cache -i veth-server -l debug`
Expected: 程序启动，BPF 程序加载成功

**Step 3: 发送测试 DNS 查询**

Run: `just send -d example.com -t A`
Expected: 
- 第一次查询: Cache miss，向上游查询
- 第二次查询: Cache hit，XDP_TX 直接响应

**Step 4: 检查日志**

Expected 日志输出:
```
[XDP] Cache miss: Hash=0x...
[TC] Captured DNS Resp: len=...
[Cache] Stored: Hash=0x... Size=... TTL=...
[XDP] Cache hit: Hash=0x...
[XDP] Reflecting response: ID=0x...
```

**Step 5: 清理**

Run: `just net-down`

---

## 完成检查清单

- [ ] Phase 3 完成: BPF Arena 集成
  - [ ] 数据结构定义
  - [ ] BPF Maps 定义
  - [ ] Arena 分配器
  - [ ] ECS Scope 检查
  - [ ] Ring Buffer 消费
  - [ ] CLI 参数支持

- [ ] Phase 4 完成: XDP 快速路径
  - [ ] 缓存查找
  - [ ] 增量校验和
  - [ ] 热修补 + XDP_TX
  - [ ] 集成测试通过

---

## 注意事项

1. **BPF 验证器限制**: XDP 程序需要通过验证器检查，可能需要调整循环和内存访问模式
2. **Arena 对齐**: 所有分配必须 512B 对齐
3. **TTL 处理**: 取所有 Answer 记录中的最小 TTL
4. **并发安全**: MVP 使用单线程，后续可扩展为 per-entry spinlock

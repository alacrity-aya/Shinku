# eBPF DNS Cache MVP 设计文档

**日期**: 2026-02-21  
**状态**: 已批准  
**版本**: v1.0

---

## 1. 设计目标

### 1.1 核心目标

| 优先级 | 目标 | 说明 |
|--------|------|------|
| P0 | 协议正确性 | 严格遵循 DNS 规范，防止缓存污染 |
| P0 | 内存效率 | 最小化内存占用，支持变长 DNS 记录 |
| P1 | 性能 | 最大化 QPS，最小化延迟 |

### 1.2 MVP 范围

- **记录类型**: A 记录 (IPv4)
- **内核版本**: Linux 6.9+ (BPF Arena)
- **ECS 策略**: Scope-Zero（仅缓存全局响应，后续迭代支持 ECS）

---

## 2. 架构设计

### 2.1 整体架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           eBPF DNS Cache MVP                             │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐                              ┌─────────────┐           │
│  │ DNS 客户端   │◄────────────────────────────►│ DNS 服务端   │           │
│  └──────┬──────┘                              └──────┬──────┘           │
│         │                                            │                  │
│         │ 查询请求                                   │ 响应报文          │
│         ▼                                            ▼                  │
│  ┌─────────────┐                              ┌─────────────┐           │
│  │ XDP Ingress │                              │  TC Egress  │           │
│  │  (Fast Path)│                              │  (Capture)  │           │
│  │             │                              │             │           │
│  │ 1.解析查询   │                              │ 1.过滤 53端口│           │
│  │ 2.计算Hash  │                              │ 2.提交RingBuf│           │
│  │ 3.查找缓存   │                              │             │           │
│  │ 4.热修补ID  │                              └──────┬──────┘           │
│  │ 5.XDP_TX   │                                     │                  │
│  └──────┬──────┘                              ┌──────▼──────┐           │
│         │                                     │ Ring Buffer │           │
│         │                                     │  (1MB)      │           │
│         │                                     └──────┬──────┘           │
│         │                                            │                  │
│         │                                     ┌──────▼──────┐           │
│         │                                     │  User Space │           │
│         │                                     │  (单线程)    │           │
│         │                                     │             │           │
│         │                                     │ 1.协议验证   │           │
│         │                                     │ 2.ECS检查   │           │
│         │                                     │ 3.压缩指针展平│           │
│         │                                     │ 4.Arena写入  │           │
│         │                                     │ 5.Map更新   │           │
│         │                                     └──────┬──────┘           │
│         │                                            │                  │
│  ┌──────▼────────────────────────────────────────────▼──────┐           │
│  │                    BPF Maps                               │           │
│  │                                                           │           │
│  │  ┌─────────────────┐    ┌─────────────────────────────┐  │           │
│  │  │   cache_map     │    │       arena (可配置大小)      │  │           │
│  │  │   (HASH)        │    │                             │  │           │
│  │  │                 │    │  Entry 0..N (每条 512B)     │  │           │
│  │  │ Key: cache_key  │    │                             │  │           │
│  │  │ Val: cache_val  │    │                             │  │           │
│  │  └─────────────────┘    └─────────────────────────────┘  │           │
│  └───────────────────────────────────────────────────────────┘           │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 组件职责

| 组件 | 位置 | 技术 | 职责 |
|------|------|------|------|
| **XDP Ingress** | Kernel (XDP) | `XDP_TX`, `bpf_arena` | Fast Path: 缓存查找、热修补、反射响应 |
| **TC Egress** | Kernel (TC) | `sk_buff`, RingBuf | Capture: 捕获 DNS 响应，提交到用户态 |
| **Control Plane** | User Space | libbpf, `bpf_arena` | 规范化引擎: ECS 检查、压缩指针展平、缓存更新 |
| **cache_map** | Kernel Map | `BPF_MAP_TYPE_HASH` | 元数据索引: Key → Arena 偏移 + 过期时间 |
| **arena** | Shared Mem | `BPF_MAP_TYPE_ARENA` | 载荷存储: 规范化的 DNS 响应包 |

---

## 3. 数据结构设计

### 3.1 cache_map Key

```c
struct cache_key {
    __u32 name_hash;   // FNV-1a 32-bit 域名哈希
    __u16 qtype;       // 查询类型 (A=1)
    __u16 qclass;      // 查询类 (IN=1)
    __u32 _pad;        // 对齐填充
};  // 12 bytes
```

### 3.2 cache_map Value

```c
struct cache_value {
    __u64 arena_offset;  // Arena 中的偏移量
    __u64 expire_ts;     // 过期时间戳 (纳秒)
    __u16 pkt_len;       // DNS 包实际长度 (≤512B)
    __u8  scope;         // ECS Scope (0=全局, >0=子网特定, MVP 不缓存)
    __u8  _pad[5];       // 对齐填充
};  // 24 bytes
```

### 3.3 Arena Entry

```c
#define ARENA_ENTRY_SIZE 512  // 传统 DNS UDP 最大包大小

struct arena_entry {
    __u8 data[ARENA_ENTRY_SIZE];  // 规范化的 DNS 响应
};
```

### 3.4 Arena 分配器

```c
struct arena_allocator {
    __u64 next_offset;      // 下一个可用位置 (bump pointer)
    __u64 capacity;         // Arena 容量 (字节)
    __u32 entry_count;      // 已分配条目数
    __u32 max_entries;      // 最大条目数
};
```

---

## 4. 数据流设计

### 4.1 Slow Path: 缓存填充

```
TC Egress → Ring Buffer → User Space → Arena → cache_map
                                │
                                ├─ 1. 协议验证 (QR=1, TC=0, RCODE=0, QDCOUNT=1)
                                ├─ 2. ECS 检查 (Scope=0 才缓存)
                                ├─ 3. 压缩指针展平
                                ├─ 4. 剥离 Additional Section
                                ├─ 5. TTL 提取 (取最小值)
                                ├─ 6. Arena 分配 (bump + freelist)
                                └─ 7. cache_map 更新
```

### 4.2 Fast Path: 缓存命中

```
XDP RX → 解析查询 → cache_map 查找 → Arena 读取 → 热修补 → XDP_TX
                                            │
                                            ├─ 1. TTL 检查 (未过期)
                                            ├─ 2. Transaction ID 替换
                                            ├─ 3. MAC/IP/Port 交换
                                            └─ 4. 增量校验和更新
```

---

## 5. 关键算法

### 5.1 增量校验和

仅当 Transaction ID 变化时，增量更新 IP/UDP 校验和：

```c
static inline void update_checksum_incremental(
    __u16 *checksum, __u16 old_val, __u16 new_val
) {
    __u32 sum = ~ntohs(*checksum) & 0xFFFF;
    sum += (~old_val & 0xFFFF);
    sum += new_val;
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);  // 处理溢出
    *checksum = htons(~sum & 0xFFFF);
}
```

### 5.2 Arena 分配

```c
// 分配策略: bump allocator + freelist
__u64 arena_alloc(struct arena_allocator *alloc) {
    // 优先从 freelist 取 (后续实现)
    // 否则 bump
    if (alloc->next_offset + ARENA_ENTRY_SIZE > alloc->capacity) {
        return ARENA_ALLOC_FAILED;  // Arena 满
    }
    __u64 offset = alloc->next_offset;
    alloc->next_offset += ARENA_ENTRY_SIZE;
    alloc->entry_count++;
    return offset;
}
```

### 5.3 Scope-Zero ECS 检查

```c
// 检查响应是否为全局响应 (Scope=0)
// 返回: 0=全局, >0=子网特定, -1=解析错误
int check_ecs_scope(const uint8_t *pkt, int arcount, int offset, int max_len);

// MVP: 只缓存 Scope=0 的响应
if (check_ecs_scope(pkt, arcount, offset, max_len) != 0) {
    return 0;  // 不缓存，直接放行
}
```

---

## 6. 设计决策

### 6.1 决策汇总

| 决策点 | 选择 | 理由 |
|--------|------|------|
| 存储方案 | 连续存储 (Arena) | MVP 简单可靠，XDP 读取只需一次 memcpy |
| 驱逐策略 | 仅 TTL 过期 | 实现简单，避免复杂 LRU |
| 并发控制 | 单线程处理 | 无锁竞争，简单可靠 |
| 校验和 | 增量更新 | 性能优化，避免完整重算 |
| ECS 策略 | Scope-Zero | 保证正确性，后续迭代支持 |
| Arena 大小 | 可配置 | 灵活部署，通过命令行参数指定 |

### 6.2 后续迭代规划

| 版本 | 功能 | 说明 |
|------|------|------|
| MVP | A 记录 + Scope-Zero | 当前设计 |
| v1.1 | AAAA 记录 | IPv6 支持 |
| v1.2 | CNAME 记录 | 别名记录支持 |
| v2.0 | ECS 完整支持 | 子网感知缓存 |

---

## 7. 实施计划

### Phase 3: BPF Arena 集成

| 任务 | 文件 | 状态 |
|------|------|------|
| 定义 Arena Map + cache_map | `cache.bpf.c` | 待实现 |
| 实现 Arena 分配器 | `src/user/arena.c` (新建) | 待实现 |
| 完善 ECS Scope 检查 | `parser.c` | 待实现 |
| Ring Buffer 消费 + 缓存更新 | `main.c` | 待实现 |

### Phase 4: XDP 快速路径

| 任务 | 文件 | 状态 |
|------|------|------|
| XDP 缓存查找逻辑 | `cache.bpf.c` | 待实现 |
| 热修补 + 增量校验和 | `cache.bpf.c` | 待实现 |
| XDP_TX 反射响应 | `cache.bpf.c` | 待实现 |

---

## 8. 参考资料

1. **CN116684385A (浙大专利)**: 离散分块存储 + 近似 LRU 驱逐
2. **BMC (NSDI'21)**: Pre-stack processing + Tail calls 拆分复杂程序
3. **RFC 1035**: DNS 协议规范
4. **RFC 7871**: EDNS Client Subnet (ECS)

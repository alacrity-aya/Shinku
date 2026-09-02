# Shinku | 高性能透明 DNS 缓存代理（eBPF / DPDK 数据面）

GitHub：https://github.com/alacrity-aya/Shinku

**项目简介**：面向高吞吐、低时延场景设计透明 DNS 缓存代理；缓存命中在 eBPF XDP 或 DPDK
用户态数据面直接构造响应，缓存异常时 fail-open 转发至上游，避免缓存故障中断 DNS 服务。

**项目经历**：

- 设计 C++ Host Runtime 与后端无关的缓存领域模型，以统一的 `probe/start/poll/stop` 生命周期驱动
  eBPF、DPDK 双后端；使用 `std::expected`、RAII 和窄 C ABI 边界显式收敛错误及内核/DPDK 资源所有权。

- 实现 eBPF 高速缓存路径：XDP 解析查询并通过 `XDP_TX` 原地直答，TC 捕获上游响应；基于
  BPF Arena、哈希索引、generation 与 seqlock 发布一致快照，并通过 Pending Query 关联阻止非请求响应写入缓存。

- 实现 DPDK 用户态数据面：以 `rte_hash` 和启动期预分配的定长 Entry slab 管理 Cache/Pending，保证启动后
  Cache Hit/Fill 无通用堆分配；命中时复用原查询 `mbuf` 构造响应，以 32 包 burst 和增量清理限制单次轮询工作量。

- 抽象 DNS 线格式解析与缓存策略，统一两种后端的 TTL 老化、Transaction ID 回填、负缓存和校验和语义；
  建立 Catch2 单元测试、BPF verifier、netns/veth 与 DPDK `net_ring` 集成测试、libFuzzer 及 Docker soak 测试链路。

- 搭建可复现的 PERF-M8-1 对照基准；在 veth + generic XDP 环境的零丢包吞吐校准中，单热名由
  102.5K 提升至 709.3K QPS（6.9 倍），4,096 域名 Zipf 负载由 101.3K 提升至 571.7K QPS（5.6 倍）；
  固定负载画像中 p50 分别由 671/623 us 降至 4/24 us，并减少整机约 1.2-1.3 核 CPU 占用。

**技术栈**：C++23/26、C、eBPF（XDP/TC、BPF Arena）、DPDK、libbpf、Linux 网络栈、DNS、Meson、Catch2、libFuzzer

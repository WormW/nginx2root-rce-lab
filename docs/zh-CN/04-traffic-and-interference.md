# 04 — 流量、耗时与干扰

## 单次尝试实测流量

数据来自 nginx 1.31.7 成功运行（1.31.8 几乎一样）：

| 阶段 | 明文 | TLS 线上字节 | 耗时 |
|---|---:|---:|---:|
| Bootstrap / oracle（`bootstrap_bytes=7,340,032` + 256 次 KeyUpdate） | 7 MiB（+TLS） | ~14 MB | ~5 s |
| 固定 carrier（960 × 16,777,215 B 帧） | 15.00 GiB | ~16.1 GB | 88.5 s |
| WINDOW_UPDATE replay（96 tranche × 1,163,220,292 B） | 104.00 GiB | 104.14 GiB | 214 s |
| 合计 | 119.02 GiB | ~119.1 GiB | 350.9 s |

- 平均：364 MB/s ≈ 2.9 Gbps
- 峰值阶段（replay）：522 MB/s ≈ 4.2 Gbps，持续约 3.5 分钟
- carrier 阶段：182 MB/s ≈ 1.5 Gbps
- 反方向（服务器 → 客户端）很小：两次泄漏 14,393 B + 200,929 B 加 HTTP/2 头。

TLS 开销只有约 0.12%（wire/application ≈ 1.0013）。

## 带宽要求

profile 的 `keepalive_time_seconds = 3600` 要求整个调度在一小时内完成：

- 理论下限：119.1 GiB / 3600 s ≈ 35.5 MB/s ≈ 285 Mbps；
- 实践建议：≥1 Gbps 独占；想 6 分钟左右完成的话建议 2–5 Gbps，否则可能
  触发 `send_timeout` 或调度门禁。

目标还要承受约 120 GiB TLS 记录的解密和处理（4 个 nginx worker），客户端
必须保持严格节奏。

## 其他客户端请求的干扰

Rapid7 文档里写得很清楚：

> The profile is intended for a fresh or lightly exercised target. Earlier
> tests after substantial prior traffic and under 16 active clients each
> failed in two attempts, despite completing the large transfer.

（profile 面向"新鲜或轻度使用"的目标；在大量先前流量和 16 个活跃客户端下，
各两次尝试都失败，尽管大传输本身完成了。）

我们的实践也一致：每次成功前都重启容器，确保 worker 堆是新鲜的；SSE 阴性
对照则在第二次泄漏处失败——说明堆阶段非常敏感。

干扰机制：

1. 堆布局 —— 利用依赖目标 worker 内 glibc arena 状态和特定 pool/chunk 相邻
   关系。同一 worker 上任何请求都会改变分配器状态，可能破坏首次泄漏、reclaim
   或第二次定址泄漏（症状：`address disclosure has 0 complete frame chains`）。
2. worker 绑定 —— 16 条 auxiliary 连接必须和主连接落在同一 worker；其他流量
   会改变 accept 分配，减少同 worker 连接池。
3. 时序 —— 调度依赖 TCP 背压窗口、`send_timeout`、keepalive 限制；争抢
   CPU/带宽造成抖动和超时。
4. 连接数 —— `worker_connections 1024`；利用自身占用主连接、16 辅助、最多
   128 并发 stream。
5. 中间设备 —— CDN/WAF 终止 TLS 再以 HTTP/1.1 回源会直接切断入口；共享限速
   /WAF 可能丢流量。
6. 检测 —— 单连接 120 GiB 入站、约 85.9 亿个 WINDOW_UPDATE 帧、worker 崩溃，
   特征极其明显。

### 对其他用户的影响

成功利用链所在 worker 会崩溃并由 master 重建（`worker process exited on
signal 6`），该 worker 上的在途请求会中断；4 Gbps 入站也会争抢 CPU 和带宽。
把这技术当成有破坏性的，只在实验环境用。

## 实验环境建议

- 用专用/安静的目标；每次尝试前重启 nginx（或容器），拿到干净的 worker 堆。
- 测试窗口内关掉或避开按 IP 限速。
- 提供 ≥1 Gbps 带宽，盯着目标 CPU。
- 尝试前先做 memcpy 门禁，别花 6 分钟才发现选错实现。
- 用目标容器里的文件等外部 oracle 验证，别只看利用自己的日志。

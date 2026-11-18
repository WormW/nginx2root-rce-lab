# 01 — 概览

## 背景

CVE-2026-123007（nginx2root）是 Xint 在 2026-11-18 披露的 nginx HTTP/2
漏洞，nginx 1.31.9 修复（稳定版回移 1.30.7）。简单说，攻击者可以让 nginx
对排队中的 DATA 帧重复返还 HTTP/2 流控信用，把连接发送窗口顶过 31 位上限；
这个值后来回绕成负的 `off_t`，在 TLS 发送链里被当成巨大的 `size_t` 传给
`memcpy`，形成一次巨大的重叠堆复制。Rapid7 的公开 PoC 把这次复制变成地址
泄漏、堆 reclaim，最后以 nginx worker 权限调用 `system()`。

影响所有开了 HTTP/2 的 nginx（1.9.5 – 1.31.8），不需要认证。

## 实验环境

| 项目 | 值 |
|---|---|
| 宿主 | 私有实验主机 |
| 目标 VM | 8 vCPU / 8 GiB，Debian 12 内核，Docker 20.10 |
| 暴露给 VM 的 CPU 型号 | IvyBridge — 只有 `avx`，没有 avx2 / avx512f / avx512vl |
| 目标 | 官方 `nginx:1.31.8`（固定 digest）和 `nginx:1.31.7` 镜像，Debian 13 用户态 |
| glibc | Debian GLIBC 2.41-12+deb13u4（`9792e3cb…`，两个镜像相同） |
| 配置 | 4 worker、`worker_connections 1024`、TLS 1.3 + `http2 on`、静态 `/index.html`（896 字节） |
| 客户端 | Rapid7 公开 PoC（只引用，不重新分发），Python + 原生 TLS record 辅助程序 |
| 目标侧调优 | `GLIBC_TUNABLES=glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load` |

## 结果

| 运行 | 目标 | memcpy 实现 | 结果 |
|---|---|---|---|
| 1 | nginx 1.31.8，官方 Rapid7 profile | AVX/YMM @ `0x162880` | 成功，marker 属 nginx 用户（UID 101） |
| 2 | nginx 1.31.7，本地标定 profile | AVX/YMM @ `0x162880` | 成功，marker 属 UID 101 |
| 3 | nginx 1.31.8，不加 tunable（阴性对照） | SSE/XMM @ `0xadd00` | 失败：`address disclosure has 0 complete frame chains` |

运行 1 和 2 各自完成 119.02 GiB 逻辑流量，耗时约 350 秒，拿到 14,393 字节
首次泄漏和 200,929 字节定址泄漏，在线解析 ASLR，并在目标容器里执行了固定
的无害命令。

## 为什么写这个仓库

主要是两个踩过的坑值得记下来：

1. AVX-512 不是必须的。公开 profile 里写了 `avx512f/avx512vl`，是因为标定
   时用的是 glibc 的 EVEX/YMM `memcpy`。利用真正依赖的是那个实现的内存
   访问几何（32 字节向量、128 字节源头部、尾部处理）。glibc 里还有几何
   等价的 AVX/YMM 实现，用官方 tunable 就能在只有 AVX 的 CPU 上选到。
2. 没有官方 profile 的版本也能适配。目标 libc 相同、nginx 版本相近时，
   只需要重算几个 nginx image 指针 delta。官方二进制被 strip，但用相对
   指针关系扫描加函数字节签名匹配就能把新 delta 恢复出来，不需要调试符号。

仓库里是脱敏后的笔记、标定工具和非敏感 profile。利用客户端本身是 Rapid7
公开代码，不在这里重新分发。

## 安全

所有工作都在授权的隔离实验机器上完成。单次尝试约 119 GiB 入站流量，可能
让 nginx worker 崩溃，在真实网络里也很显眼。别对未授权系统使用，详见
[DISCLAIMER.md](../../DISCLAIMER.md)。

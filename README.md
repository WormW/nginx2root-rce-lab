# nginx2root RCE Lab

**中文**（默认） | [English](README.en.md)

记录我们复现 CVE-2026-123007（nginx2root，nginx HTTP/2 RCE）的过程，以及
顺手解决的两个实际问题：

- 没有 AVX-512 的机器也能打。公开 profile 里写的 `required_cpu_flags`
  容易让人以为必须 AVX-512，其实关键是 glibc 选中的 `memcpy` 实现的
  内存访问几何。用官方 `GLIBC_TUNABLES` 就能在只有 AVX 的 CPU 上选到
  等价的 AVX/YMM 实现。
- 没有官方 profile 的版本也能适配。我们以 nginx 1.31.7 为例，从被 strip
  的二进制里把几个 nginx image 指针 delta 重新算出来，跑通了完整利用链。

仓库里还有正/负对照（AVX/YMM 成功、SSE 失败）、实测流量和干扰情况，
以及我们用的几个小工具。

> 仅限授权实验环境。一次尝试大约 119 GiB 入站流量，还可能把 nginx worker
> 打崩，别往生产或别人的机器上跑。详见 [DISCLAIMER.md](DISCLAIMER.md)。

## 结果

| 目标 | nginx | memcpy 路径 | 结果 |
|---|---|---|---|
| 官方镜像 + 官方 profile | 1.31.8 | AVX/YMM `0x162880` | RCE，marker 属 nginx 用户（UID 101） |
| 官方镜像 + 本地标定 profile | 1.31.7 | AVX/YMM `0x162880` | RCE，marker 属 UID 101 |
| 官方镜像，不加 tunable | 1.31.8 | SSE/XMM `0xadd00` | 第二次泄漏失败，无 marker |

两次成功都是约 119 GiB 逻辑流量、350 秒左右（8 vCPU 实验 VM），峰值约
4.2 Gbps。目标最好是"新鲜、安静"的：别的请求会打乱 worker 的堆布局，
我们每次成功前都重启了容器。

## 目录

```
docs/zh-CN/    中文笔记（背景、memcpy 几何、版本标定、流量与干扰）
docs/en/       对应的英文版
tools/         memcpy 门禁、HTTP/2 探测、delta 扫描、函数签名匹配、profile 生成
profiles/      本地标定的 nginx 1.31.7 profile
scripts/       实验启动 / 尝试 / 收集证据的模板脚本
evidence/      运行日志节选（已脱敏）
```

## 快速开始

1. 准备一台 x86-64 Linux 主机，按 Rapid7 的复现配置启动固定版本 nginx
   镜像，并注入选择 AVX/YMM `memcpy` 的 tunable：

   ```sh
   export NGINX_IMAGE='nginx:1.31.8'
   export GLIBC_TUNABLES='glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load'
   # 见 scripts/setup_target.sh
   ```

2. 在目标容器里确认 `memcpy` 偏移：

   ```sh
   cc -O2 -Wall -o memcpy_gate tools/memcpy_gate.c -ldl
   docker cp memcpy_gate <container>:/tmp/memcpy_gate
   docker exec <container> /tmp/memcpy_gate
   # AVX/YMM: 0x162880   EVEX/YMM: 0x1727c0   SSE: 0xadd00
   ```

3. 拉 Rapid7 公开 PoC（本仓库不重新分发），构建客户端，对刚重启的目标
   跑一次。步骤见 [版本标定](docs/zh-CN/03-calibration.md) 和
   [scripts/run_attempt.sh](scripts/run_attempt.sh)。

## 给别的版本做标定

如果目标 libc 和已知 profile 一致（同一个 glibc），相近的 nginx 构建通常
只需要重算几个 image 指针 delta：

```sh
python3 tools/scan_nginx_deltas.py <old-nginx> --profile <known-profile.json>
python3 tools/match_nginx_functions.py <old-nginx> <new-nginx> \
    --old-anchor 0x... --functions 0x...
python3 tools/make_profile.py --base <known-profile.json> \
    --nginx <new-nginx> --libc <libc.so.6> --name local-nginx-<ver> \
    --deltas ... --out profiles/local-nginx-<ver>.json
```

1.31.8 → 1.31.7 的例子：delta 从
`send_chain +139856 / resolver -310400 / destroy_pool -398896` 变成
`+139984 / -310784 / -399344`，heap 和 transport 参数不用动。

## 文档

- [概览](docs/zh-CN/01-overview.md) · [English](docs/en/01-overview.md)
- [memcpy 几何](docs/zh-CN/02-memcpy-geometry.md) · [English](docs/en/02-memcpy-geometry.md)
- [版本标定](docs/zh-CN/03-calibration.md) · [English](docs/en/03-calibration.md)
- [流量与干扰](docs/zh-CN/04-traffic-and-interference.md) · [English](docs/en/04-traffic-and-interference.md)

## 参考

- Xint 披露站：https://nginx2root.com/
- Xint 技术分析：https://xint.io/blog/nginx2root-remote-code-execution
- Rapid7 公开 PoC：https://github.com/sfewer-r7/CVE-2026-123007
- nginx 1.31.9 修复：https://github.com/nginx/nginx/releases/tag/release-1.31.9

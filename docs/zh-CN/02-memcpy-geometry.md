# 02 — 为什么 AVX-512 不是必须的

## 容易误导的 profile 字段

Rapid7 公开 profile（`golden-nginx-1.31.8-debian13-amd64`）里有这么一段：

```json
"libc": {
  "memcpy_runtime_offset": 1517504,
  "memcpy_variant": "glibc EVEX/YMM unaligned implementation",
  "memcpy_vector_bytes": 32,
  "required_cpu_flags": ["avx512f", "avx512vl"]
}
```

`1517504` 就是 `0x1727c0`，是镜像里 Debian 13 glibc 的 EVEX/YMM `memcpy`
偏移。`required_cpu_flags` 让不少没有 AVX-512 的复现（包括我们一开始）直接
卡住。

## 利用真正依赖什么

溢出路径用巨大且重叠的长度调 `memcpy`。只有选中的 `memcpy` 实现和标定时的
EVEX/YMM 行为一致，利用才能走下去：

- 主循环用 32 字节（YMM）向量；
- 读写 128 字节源头部；
- 保存 32 字节尾部（`src+n-0x20`），以同样方式对齐目的尾部，再写回相同的
  头/尾布局。

EVEX 编码（`vmovdqu64`、ymm16+）和 AVX 编码（`vmovdqu`、ymm0+）的区别只在
指令编码和末尾的 `vzeroupper`，源/目的访问位置完全一样。而 16 字节的
SSE/XMM 实现会复制不同的区间，把后面利用依赖的 B/C 重叠破坏掉。

## 同一个 libc 里的三种实现

针对 glibc `2.41-12+deb13u4`（Debian 13 amd64，SHA-256 `9792e3cb…`）：

| 运行时偏移 | 实现 | 编码 | 向量宽度 |
|---|---|---|---|
| `0x1727c0` | `__memmove_evex_unaligned_erms` 类 | EVEX/YMM（`vmovdqu64`） | 32 B |
| `0x162880` | AVX/YMM unaligned | AVX（`vmovdqu`） | 32 B |
| `0xadd00` | SSE/XMM unaligned | SSE（`movdqu`） | 16 B |

Rapid7 profile 的标定后端叫 `x86-64-glibc-evex-v1`，只是因为标定时用了那个
实现，不代表利用会执行 AVX-512 指令。

## 选中等价实现

glibc 通过 IFUNC 按 CPU 特性选 `memcpy`。官方 tunable `glibc.cpu.hwcaps`
可以强制启用 "fast unaligned AVX load" 特性，在支持 AVX 但不支持 AVX-512
的 CPU 上选中 AVX/YMM 实现：

```sh
GLIBC_TUNABLES=glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load
```

这个变量必须在动态加载器运行前就在 nginx 进程环境里。Docker 里用 `-e`
传进容器，nginx worker 从 master 继承。

我们在目标容器里用 [`tools/memcpy_gate.c`](../../tools/memcpy_gate.c) 验证：

```text
$ docker exec <container> /tmp/memcpy_gate
memcpy=0x7f... libc_base=0x7f... offset=0x162880
GLIBC_TUNABLES=glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load

$ docker exec -e GLIBC_TUNABLES= <container> /tmp/memcpy_gate
memcpy=0x7f... libc_base=0x7f... offset=0xadd00
GLIBC_TUNABLES=(unset)
```

只看偏移就能做很强的门禁判断：SSE 路径会在第二次定址泄漏处稳定失败，报
`address disclosure has 0 complete frame chains`；AVX/YMM 路径能跑完全链。

## 两次成功运行的对比

nginx 1.31.8 和 1.31.7 镜像带的是同一个 libc（`9792e3cb…`），所以同一个
tunable 在两个容器里都得到 `0x162880`，libc 相对字段（`system` 解析、arena
偏移）也继续有效。

## 实操清单

1. 从目标镜像提取 `libc.so.6`，和已标定 profile 的 SHA-256 对比。相同则
   memcpy/arena/system 标定可复用；不同就要重新标定这些值。
2. 在目标进程环境里确认解析到的 `memcpy` 偏移。
3. 如果是 EVEX/YMM 或 AVX/YMM（32 字节几何），链可以继续；如果是 SSE/XMM，
   基本会在第二次泄漏失败。
4. tunable 只是实验复现手段，别当成生产缓解措施。

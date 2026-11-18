# 01 — Overview

## Background

CVE-2026-123007 (nginx2root) is an nginx HTTP/2 vulnerability disclosed by
Xint on 2026-11-18 and fixed in nginx 1.31.9 (stable backport 1.30.7). In
short, a client can make nginx refund HTTP/2 flow-control credit twice for
queued DATA frames, pushing the connection send window past its 31-bit limit.
That value later wraps into a negative `off_t`, which the TLS staging path
treats as a huge `size_t` and hands to `memcpy`, producing a huge overlapping
heap copy. Rapid7's public PoC turns that copy into an address disclosure, a
heap reclaim, and finally a `system()` call with nginx worker privileges.

It affects every nginx with HTTP/2 enabled (1.9.5 – 1.31.8) and needs no
authentication.

## Lab setup

| Item | Value |
|---|---|
| Host | private lab machine |
| Target VM | 8 vCPU / 8 GiB, Debian 12 kernel, Docker 20.10 |
| CPU model exposed to the VM | IvyBridge — `avx` only, no avx2 / avx512f / avx512vl |
| Targets | official `nginx:1.31.8` (pinned digest) and `nginx:1.31.7` images, Debian 13 userland |
| glibc | Debian GLIBC 2.41-12+deb13u4 (`9792e3cb…`, identical in both images) |
| Config | 4 workers, `worker_connections 1024`, TLS 1.3 + `http2 on`, static `/index.html` (896 bytes) |
| Client | Rapid7 public PoC (referenced, not redistributed), Python + native TLS record helper |
| Target-side tuning | `GLIBC_TUNABLES=glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load` |

## Results

| Run | Target | memcpy implementation | Result |
|---|---|---|---|
| 1 | nginx 1.31.8, official Rapid7 profile | AVX/YMM @ `0x162880` | success, marker owned by nginx user (UID 101) |
| 2 | nginx 1.31.7, locally calibrated profile | AVX/YMM @ `0x162880` | success, marker owned by UID 101 |
| 3 | nginx 1.31.8, no tunable (negative control) | SSE/XMM @ `0xadd00` | failed: `address disclosure has 0 complete frame chains` |

Runs 1 and 2 each moved 119.02 GiB of logical traffic in about 350 seconds,
captured the 14,393-byte first disclosure and the 200,929-byte
address-directed disclosure, resolved ASLR in-band, and ran a fixed benign
command inside the target container.

## Why this repo exists

Two gotchas are worth writing down:

1. AVX-512 isn't required. The public profile lists `avx512f/avx512vl` because
   calibration used glibc's EVEX/YMM `memcpy`. What the exploit really depends
   on is that implementation's memory-access geometry (32-byte vectors,
   128-byte source head, tail handling). glibc ships a geometry-equivalent
   AVX/YMM implementation, and an official tunable selects it on AVX-only CPUs.
2. Versions without an official profile can be adapted. When the target libc
   matches and the nginx version is close, only a few nginx-image pointer
   deltas need recomputing. The official binary is stripped, but relative
   pointer scanning plus function byte-signature matching recovers the new
   deltas without debug symbols.

The repo contains sanitized notes, calibration tooling and non-sensitive
profiles. The exploit client itself is Rapid7's public code and isn't
redistributed here.

## Safety

Everything was done on authorized, isolated lab machines. One attempt moves
about 119 GiB inbound, can crash an nginx worker, and is very visible on a
real network. Don't use it against systems you don't own. See
[DISCLAIMER.md](../../DISCLAIMER.md).

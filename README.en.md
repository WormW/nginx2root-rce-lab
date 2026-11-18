# nginx2root RCE Lab

**English** | [中文](README.md)

Notes and tooling from reproducing CVE-2026-123007 (nginx2root, the nginx
HTTP/2 RCE) in our lab, plus two problems we ran into along the way:

- You don't need AVX-512. The `required_cpu_flags` in the public profile makes
  it look mandatory, but what actually matters is the memory-access geometry
  of the `memcpy` implementation glibc picks. An official `GLIBC_TUNABLES`
  setting selects an equivalent AVX/YMM implementation on AVX-only CPUs.
- Versions without an official profile can be adapted. Using nginx 1.31.7 as
  an example, we recovered the nginx-image pointer deltas from the stripped
  binary and got the full chain working.

The repo also has a positive/negative control pair (AVX/YMM works, SSE fails),
measured traffic and interference notes, and the small tools we used.

> Authorized lab use only. One attempt moves about 119 GiB inbound and can
> crash an nginx worker. Don't point it at production or other people's
> machines. See [DISCLAIMER.md](DISCLAIMER.md).

## Results

| Target | nginx | memcpy path | Result |
|---|---|---|---|
| Official image + official profile | 1.31.8 | AVX/YMM `0x162880` | RCE, marker owned by nginx user (UID 101) |
| Official image + local profile | 1.31.7 | AVX/YMM `0x162880` | RCE, marker owned by UID 101 |
| Official image, no tunable | 1.31.8 | SSE/XMM `0xadd00` | fails at the second disclosure, no marker |

Both successful runs moved ~119 GiB of logical traffic in about 350 seconds
on an 8-vCPU lab VM, peaking around 4.2 Gbps. The target should be fresh and
quiet: other requests disturb the worker's heap layout, so we restarted the
container before every successful attempt.

## Layout

```
docs/zh-CN/    Chinese notes (background, memcpy geometry, calibration, traffic)
docs/en/       English versions
tools/         memcpy gate, HTTP/2 probe, delta scanner, function matcher, profile generator
profiles/      locally calibrated nginx 1.31.7 profile
scripts/       lab setup / attempt / evidence templates
evidence/      sanitized log excerpts
```

## Quick start

1. On an x86-64 Linux host, start the pinned nginx image with the Rapid7 lab
   config and inject the tunable that selects the AVX/YMM `memcpy`:

   ```sh
   export NGINX_IMAGE='nginx:1.31.8'
   export GLIBC_TUNABLES='glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load'
   # see scripts/setup_target.sh
   ```

2. Check the `memcpy` offset inside the target container:

   ```sh
   cc -O2 -Wall -o memcpy_gate tools/memcpy_gate.c -ldl
   docker cp memcpy_gate <container>:/tmp/memcpy_gate
   docker exec <container> /tmp/memcpy_gate
   # AVX/YMM: 0x162880   EVEX/YMM: 0x1727c0   SSE: 0xadd00
   ```

3. Fetch the public Rapid7 PoC (not redistributed here), build its client,
   and run an attempt against a freshly restarted target. See
   [the calibration notes](docs/en/03-calibration.md) and
   [scripts/run_attempt.sh](scripts/run_attempt.sh).

## Calibrating another version

If the target libc matches a known profile (same glibc), a nearby nginx build
usually only needs its image pointer deltas recomputed:

```sh
python3 tools/scan_nginx_deltas.py <old-nginx> --profile <known-profile.json>
python3 tools/match_nginx_functions.py <old-nginx> <new-nginx> \
    --old-anchor 0x... --functions 0x...
python3 tools/make_profile.py --base <known-profile.json> \
    --nginx <new-nginx> --libc <libc.so.6> --name local-nginx-<ver> \
    --deltas ... --out profiles/local-nginx-<ver>.json
```

For 1.31.8 → 1.31.7 the deltas changed from
`send_chain +139856 / resolver -310400 / destroy_pool -398896` to
`+139984 / -310784 / -399344`; heap and transport parameters stayed the same.

## Documentation

- [Overview](docs/en/01-overview.md) · [中文](docs/zh-CN/01-overview.md)
- [memcpy geometry](docs/en/02-memcpy-geometry.md) · [中文](docs/zh-CN/02-memcpy-geometry.md)
- [Version calibration](docs/en/03-calibration.md) · [中文](docs/zh-CN/03-calibration.md)
- [Traffic & interference](docs/en/04-traffic-and-interference.md) · [中文](docs/zh-CN/04-traffic-and-interference.md)

## References

- Xint disclosure: https://nginx2root.com/
- Xint write-up: https://xint.io/blog/nginx2root-remote-code-execution
- Rapid7 public PoC: https://github.com/sfewer-r7/CVE-2026-123007
- nginx 1.31.9 fix: https://github.com/nginx/nginx/releases/tag/release-1.31.9

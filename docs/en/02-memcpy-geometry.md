# 02 — Why AVX-512 isn't required

## The misleading profile field

The public Rapid7 profile (`golden-nginx-1.31.8-debian13-amd64`) contains:

```json
"libc": {
  "memcpy_runtime_offset": 1517504,
  "memcpy_variant": "glibc EVEX/YMM unaligned implementation",
  "memcpy_vector_bytes": 32,
  "required_cpu_flags": ["avx512f", "avx512vl"]
}
```

`1517504` is `0x1727c0`, the offset of the EVEX/YMM `memcpy` in the image's
Debian 13 glibc. The `required_cpu_flags` line stopped a lot of reproductions
on hosts without AVX-512 — including ours at first.

## What the exploit actually needs

The overflow path calls `memcpy` with a huge, overlapping length. The exploit
only survives if the selected `memcpy` implementation behaves like the
calibrated EVEX/YMM one:

- 32-byte (YMM) vectors in the main loop;
- reads and writes a 128-byte source head;
- saves a 32-byte tail (`src+n-0x20`), aligns the destination tail the same
  way, then writes back the same head/tail layout.

The EVEX encodings (`vmovdqu64`, ymm16+) and the AVX encodings (`vmovdqu`,
ymm0+) differ only in instruction encoding and a trailing `vzeroupper`; the
source/destination access positions are identical. A 16-byte SSE/XMM
implementation copies different ranges and destroys the B/C overlap the rest
of the exploit relies on.

## Three implementations in one libc

For glibc `2.41-12+deb13u4` (Debian 13 amd64, SHA-256 `9792e3cb…`):

| Runtime offset | Implementation | Encoding | Vector width |
|---|---|---|---|
| `0x1727c0` | `__memmove_evex_unaligned_erms`-class | EVEX/YMM (`vmovdqu64`) | 32 B |
| `0x162880` | AVX/YMM unaligned | AVX (`vmovdqu`) | 32 B |
| `0xadd00` | SSE/XMM unaligned | SSE (`movdqu`) | 16 B |

The Rapid7 profile's calibration backend is named `x86-64-glibc-evex-v1`
simply because that implementation was used during calibration, not because
the exploit executes AVX-512 instructions.

## Selecting the equivalent implementation

glibc picks `memcpy` through IFUNC based on CPU features. The official
`glibc.cpu.hwcaps` tunable can force the "fast unaligned AVX load" feature,
which selects the AVX/YMM implementation on CPUs that support AVX but not
AVX-512:

```sh
GLIBC_TUNABLES=glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load
```

The variable has to be in the nginx process environment before the dynamic
loader runs. In Docker, pass it with `-e`; nginx workers inherit it from the
master.

We verified the selection inside the target container with
[`tools/memcpy_gate.c`](../../tools/memcpy_gate.c):

```text
$ docker exec <container> /tmp/memcpy_gate
memcpy=0x7f... libc_base=0x7f... offset=0x162880
GLIBC_TUNABLES=glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load

$ docker exec -e GLIBC_TUNABLES= <container> /tmp/memcpy_gate
memcpy=0x7f... libc_base=0x7f... offset=0xadd00
GLIBC_TUNABLES=(unset)
```

The offset alone is a strong gate: the SSE path reliably fails at the second
address-directed disclosure with `address disclosure has 0 complete frame
chains`, while the AVX/YMM path completes the chain.

## Comparing the two successful runs

The nginx 1.31.8 and 1.31.7 images ship the same libc (`9792e3cb…`), so the
same tunable produced `0x162880` in both containers, and the libc-relative
fields (`system` resolution, arena offsets) stayed valid.

## Practical checklist

1. Extract `libc.so.6` from the target image and compare its SHA-256 with a
   calibrated profile. Same libc → memcpy/arena/system calibration can be
   reused; different libc → recalibrate those values.
2. Confirm the resolved `memcpy` offset in the target process environment.
3. EVEX/YMM or AVX/YMM (32-byte geometry) means the chain can proceed;
   SSE/XMM means expect failure at the second disclosure.
4. The tunable is a reproduction aid, not a production mitigation.

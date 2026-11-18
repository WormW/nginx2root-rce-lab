# Evidence

Sanitized excerpts from our lab runs:

| File | Content |
|---|---|
| `1.31.8-success-excerpt.log` | INFO-level stages of the successful nginx 1.31.8 run |
| `1.31.7-success-excerpt.log` | INFO-level stages of the successful uncalibrated nginx 1.31.7 run |
| `negative-control-sse-excerpt.log` | nginx 1.31.8 without the glibc tunable: failure at the second disclosure |
| `memcpy-gate.txt` | memcpy IFUNC offsets with and without the tunable |
| `markers.md` | marker file metadata (content redacted) |

Sanitization: lab host addresses, SSH details, container host paths and the
literal marker strings were removed. ASLR addresses in the logs are per-run
values and carry no lab identity.

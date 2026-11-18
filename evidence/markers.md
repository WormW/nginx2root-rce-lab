# Marker oracle evidence

The exploit was asked to run a fixed benign command whose only effect is
creating a small marker file inside the target container. Marker contents are
redacted; their sizes and ownership are the evidence.

## nginx 1.31.8 (official profile, AVX/YMM memcpy)

```text
uid=101 gid=101 mode=644 size=13 mtime=<matches the exploit log>
content: redacted (13-byte benign string)
```

## nginx 1.31.7 (locally calibrated profile, AVX/YMM memcpy)

```text
uid=101 gid=101 mode=644 size=14 mtime=<matches the exploit log>
content: redacted (14-byte benign string)
```

`uid=gid=101` is the unprivileged `nginx` user in the official image, which
confirms command execution with nginx worker privileges.

## Negative control

The nginx 1.31.8 target without the glibc tunable (SSE/XMM memcpy) produced
no marker; the exploit aborted with:

```text
address disclosure capture: wire_bytes=0
ERROR exploit failed after 343.03s: address disclosure has 0 complete frame chains
```

#!/usr/bin/env bash
# Collect a small, non-sensitive evidence bundle from the target container.
#
# Authorized lab use only.
set -euo pipefail

CONTAINER="${CONTAINER:-nginx2root-target}"
HOST_PORT="${HOST_PORT:-19443}"
MARKER="${MARKER:-/tmp/nginx2root-lab-ok}"

echo "== nginx =="
docker exec "$CONTAINER" nginx -v

echo "== memcpy gate (needs /tmp/memcpy_gate copied in) =="
docker exec "$CONTAINER" /tmp/memcpy_gate || true

echo "== HTTP/2 fingerprint =="
curl -skS --http2 -D - -o /dev/null "https://127.0.0.1:${HOST_PORT}/index.html" | head -n 6

echo "== marker oracle =="
docker exec "$CONTAINER" sh -c \
    "stat -c 'uid=%u gid=%g mode=%a size=%s mtime=%y' $MARKER 2>/dev/null; \
     echo -n 'hex='; od -An -tx1 $MARKER 2>/dev/null | tr -d ' \n'; echo; \
     echo -n 'text='; cat $MARKER 2>/dev/null; echo" || true

echo "== worker exits =="
docker logs "$CONTAINER" 2>&1 | grep -E "exited on signal|start worker process" | tail -n 6 || true

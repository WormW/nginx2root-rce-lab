#!/usr/bin/env bash
# Start a pinned nginx HTTP/2 target for CVE-2026-123007 lab research.
#
# Authorized lab use only. This script:
#   - runs the official nginx image on 127.0.0.1:<HOST_PORT>
#   - injects GLIBC_TUNABLES so glibc selects the AVX/YMM memcpy geometry
#   - expects an nginx.conf from the Rapid7 reproduction recipe (see docs)
#
# Environment variables:
#   NGINX_IMAGE   nginx image/tag (default: nginx:1.31.8)
#   HOST_PORT     loopback port to publish 443 on (default: 19443)
#   CONTAINER     docker container name (default: nginx2root-target)
#   NGINX_CONF    path to nginx.conf (required)
#   GLIBC_TUNABLES (default: glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load)
set -euo pipefail

NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.31.8}"
HOST_PORT="${HOST_PORT:-19443}"
CONTAINER="${CONTAINER:-nginx2root-target}"
NGINX_CONF="${NGINX_CONF:-./lab/nginx.conf}"
GLIBC_TUNABLES="${GLIBC_TUNABLES:-glibc.cpu.hwcaps=AVX_Fast_Unaligned_Load}"

if [[ ! -f "$NGINX_CONF" ]]; then
    echo "missing nginx.conf: $NGINX_CONF" >&2
    echo "create it from the Rapid7 standalone reproduction recipe" >&2
    exit 1
fi

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

docker run -d --name "$CONTAINER" --platform linux/amd64 \
    -p "127.0.0.1:${HOST_PORT}:443" \
    -e "GLIBC_TUNABLES=${GLIBC_TUNABLES}" \
    --mount type=bind,src="$(realpath "$NGINX_CONF")",dst=/etc/nginx/nginx.conf,readonly \
    --entrypoint sh "$NGINX_IMAGE" -c '
        openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
            -keyout /tmp/nginx-h2.key -out /tmp/nginx-h2.crt \
            -subj /CN=localhost \
            -addext subjectAltName=DNS:localhost,IP:127.0.0.1 &&
        exec nginx -g "daemon off;"'

echo "container=$CONTAINER image=$NGINX_IMAGE port=127.0.0.1:${HOST_PORT}"
for _ in $(seq 1 20); do
    if curl -skS --http2 -o /dev/null "https://127.0.0.1:${HOST_PORT}/index.html"; then
        echo "target is up"
        exit 0
    fi
    sleep 0.5
done
echo "target did not become ready" >&2
docker logs "$CONTAINER" >&2 || true
exit 1

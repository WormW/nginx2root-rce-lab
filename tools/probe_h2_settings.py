#!/usr/bin/env python3
"""Minimal HTTP/2 fingerprint probe for a TLS listener.

Prints the negotiated TLS version/cipher/ALPN and the server's HTTP/2
SETTINGS pairs. Useful to compare a target with a calibration profile
before running the full exploit.

Usage:
    python3 probe_h2_settings.py <host> <port>
    python3 probe_h2_settings.py 127.0.0.1 19443

Authorized lab use only. See DISCLAIMER.md.
"""
import socket
import ssl
import struct
import sys


def main():
    if len(sys.argv) != 3:
        print("usage: probe_h2_settings.py <host> <port>", file=sys.stderr)
        return 2
    host, port = sys.argv[1], int(sys.argv[2])

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    raw = socket.create_connection((host, port), timeout=5)
    sock = ctx.wrap_socket(raw, server_hostname=host)
    print("tls_version:", sock.version())
    print("cipher:", sock.cipher()[0])
    print("alpn:", sock.selected_alpn_protocol())

    sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    sock.sendall(struct.pack(">I", 0)[1:] + bytes([0x4, 0]) + struct.pack(">I", 0))

    buf = b""
    settings = []
    sock.settimeout(3)
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 9:
                length = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + length:
                    break
                ftype = buf[3]
                flags = buf[4]
                payload = buf[9:9 + length]
                buf = buf[9 + length:]
                if ftype == 0x4 and not (flags & 0x1):
                    for i in range(0, length, 6):
                        ident = int.from_bytes(payload[i:i + 2], "big")
                        value = int.from_bytes(payload[i + 2:i + 6], "big")
                        settings.append([ident, value])
    except socket.timeout:
        pass
    finally:
        sock.close()

    print("http2_settings:", settings)
    return 0


if __name__ == "__main__":
    sys.exit(main())

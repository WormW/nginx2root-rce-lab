#!/usr/bin/env python3
"""Match function byte signatures between two (stripped) nginx binaries.

Given an old nginx binary, its anchor address and a list of function virtual
addresses, find the same functions in a new nginx binary by searching for
their leading bytes. The executable segments are mapped through the ELF
program headers; no symbols are required.

Usage:
    python3 match_nginx_functions.py OLD NEW \
        --old-anchor 0x98840 --new-anchor 0x98940 \
        --functions 0x98840,0x98670,0x95340,0xbaa90,0x4cbc0,0x37210

The function list is usually: anchor, the two relative handlers, and the
three delta targets from a calibrated profile (order matters only for the
printed table).

Authorized lab use only. See DISCLAIMER.md.
"""
import argparse
import struct
import sys


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


def vaddr_to_offset(segments, vaddr):
    for p_offset, p_vaddr, size in segments:
        if p_vaddr <= vaddr < p_vaddr + size:
            return p_offset + (vaddr - p_vaddr)
    return None


def offset_to_vaddr(segments, offset):
    for p_offset, p_vaddr, size in segments:
        if p_offset <= offset < p_offset + size:
            return p_vaddr + (offset - p_offset)
    return None


def find_signature(old_data, old_segments, old_va, new_data, new_segments):
    old_off = vaddr_to_offset(old_segments, old_va)
    if old_off is None:
        return None, 0
    for length in (96, 64, 48, 32, 24, 16):
        pattern = old_data[old_off:old_off + length]
        if len(pattern) < length:
            continue
        for p_offset, _, size in new_segments:
            idx = new_data.find(pattern, p_offset, p_offset + size)
            if idx < 0:
                continue
            vaddr = offset_to_vaddr(new_segments, idx)
            if vaddr is not None:
                return vaddr, length
    return None, 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old")
    parser.add_argument("new")
    parser.add_argument("--old-anchor", required=True)
    parser.add_argument("--new-anchor", required=True)
    parser.add_argument("--functions", required=True,
                        help="comma-separated old-binary function vaddrs")
    args = parser.parse_args()

    old_anchor = int(args.old_anchor, 0)
    new_anchor = int(args.new_anchor, 0)
    functions = [int(item, 0) for item in args.functions.split(",") if item]

    with open(args.old, "rb") as handle:
        old_data = handle.read()
    with open(args.new, "rb") as handle:
        new_data = handle.read()
    old_segments = parse_exec_segments(old_data)
    new_segments = parse_exec_segments(new_data)

    print(f"old_anchor=0x{old_anchor:x} new_anchor=0x{new_anchor:x}")
    print(f"{'old_va':>10} {'new_va':>10} {'new_delta':>12} {'match':>6}")
    for old_va in functions:
        new_va, length = find_signature(
            old_data, old_segments, old_va, new_data, new_segments)
        old_delta = old_va - old_anchor
        if new_va is None:
            print(f"0x{old_va:08x} {'not found':>10} "
                  f"(old_delta {old_delta:+d})")
            continue
        new_delta = new_va - new_anchor
        label = f"{length}B" if length == 96 else f"{length}B*"
        print(f"0x{old_va:08x} 0x{new_va:08x} {new_delta:+12d} {label:>6}"
              f"   old_delta={old_delta:+d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

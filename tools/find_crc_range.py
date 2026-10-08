#!/usr/bin/env python3
"""Search for the byte range covered by the QSPI entry-table `crc32` field.

Background
----------
Each QSPI entry header carries `name[16] | offset | size | crc32 | ext`. The
`crc32` field does **not** validate against the entry's declared payload
(FINDINGS.md §8.1.3), yet the device computes a CRC-32 (reflected, poly
`0xEDB88320`, computed at runtime — SECONDARY_MCU.md) over *something*.

This tool brute-forces candidate (rule, dialect) combinations and checks
whether a CRC over `member[start:end]` reproduces the stored field for the
*same* entry in **all three releases at once** (a correct rule must validate
across versions, which prunes false positives fast).

Start rules tried:
  abs0     start = 0x00            (member start)
  abs0x20  start = 0x20            (QSPI magic)
  abs0x28  start = 0x28
  abs0x30  start = 0x30            (entry table)
  entry    start = e.offset        (declared payload)
  hdr0x20  start = e.offset - 0x20 (include the entry header)

`end` is always the entry's declared end (`e.offset + e.size`).

Dialects tried (per range): stock reflected zlib CRC-32, its no-final-xor
variant (JAMCRC), the direct/non-reflected CRC-32 (poly 0x04C11DB7) with and
without final xor, and 16-bit hi/lo truncations of the reflected result.

Usage:
    python3 tools/find_crc_range.py [--version 182 ...] [--member C1C ...]

Exit status 0 when at least one (rule, dialect) validates an entry across all
versions, else 1.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]

# Direct (non-reflected) CRC-32 table, poly 0x04C11DB7 (MSB-first).
_DIRECT_TABLE = []
for _i in range(256):
    _c = _i << 24
    for _ in range(8):
        _c = ((_c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if _c & 0x80000000 else (_c << 1) & 0xFFFFFFFF
    _DIRECT_TABLE.append(_c)


def crc_direct(data: bytes, init: int = 0xFFFFFFFF) -> int:
    crc = init
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _DIRECT_TABLE[((crc >> 24) ^ b) & 0xFF]
    return crc


START_RULES = ("abs0", "abs0x20", "abs0x28", "abs0x30", "entry", "hdr0x20")
DIALECTS = ("zlib", "jamcrc", "direct", "direct_xor", "zlib_lo16", "zlib_hi16")


def start_for(rule: str, e) -> int:
    return {
        "abs0": 0,
        "abs0x20": 0x20,
        "abs0x28": 0x28,
        "abs0x30": 0x30,
        "entry": e.offset,
        "hdr0x20": e.offset - 0x20,
    }[rule]


def variants(data: bytes) -> dict[str, int]:
    z = zlib.crc32(data) & 0xFFFFFFFF
    d = crc_direct(data)
    return {
        "zlib": z,
        "jamcrc": z ^ 0xFFFFFFFF,
        "direct": d,
        "direct_xor": d ^ 0xFFFFFFFF,
        "zlib_lo16": z & 0xFFFF,
        "zlib_hi16": z >> 16,
    }


def load_versions(versions: list[str], members: list[str]):
    """{(member_base, entry_name): {version: (member_bytes, entry)}}"""
    by_key: dict[tuple[str, str], dict[str, tuple[bytes, object]]] = {}
    cache: dict[str, list] = {}
    for v in versions:
        raw = fw.load_container(REPO / f"mc101_sys_v{v}.zip")
        cache[v] = fw.parse_tar(raw)
    for v in versions:
        for m in cache[v]:
            base = m.name.split("/")[-1]
            if not any(mem in base for mem in members):
                continue
            if not fw.is_qspi(m.data):
                continue
            img = fw.parse_qspi(m.data)
            for e in img.entries:
                by_key.setdefault((base, e.name.strip()), {})[v] = (m.data, e)
    return by_key


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="append", default=[],
                    help="version digits, e.g. 182 (repeatable; default all three)")
    ap.add_argument("--member", action="append", default=[],
                    help="tar member substring, e.g. C1C (repeatable; default C1C C0C C1A)")
    args = ap.parse_args(argv)

    versions = args.version or ["180", "181", "182"]
    members = args.member or ["C1C", "C0C", "C1A"]

    by_key = load_versions(versions, members)
    common = {k: d for k, d in by_key.items() if all(v in d for v in versions)}

    print(f"versions: {', '.join(versions)}   members: {', '.join(members)}")
    print(f"entries present in every version: {len(common)}")
    print()

    from collections import Counter

    hits: Counter = Counter()
    detail: dict[tuple, list] = {}

    for (base, name), per_ver in sorted(common.items()):
        for rule in START_RULES:
            for dialect in DIALECTS:
                ok_all = True
                sample = None
                for v in versions:
                    data, e = per_ver[v]
                    start = start_for(rule, e)
                    end = min(e.offset + e.size, len(data))
                    if not (0 <= start < end):
                        ok_all = False
                        break
                    got = variants(data[start:end])[dialect]
                    if got != e.crc:
                        ok_all = False
                        break
                    if sample is None:
                        sample = (v, hex(got), hex(e.crc))
                if ok_all:
                    hits[(rule, dialect)] += 1
                    detail.setdefault((rule, dialect), []).append((base, name, sample))

    print("(range rule, crc dialect) -> entries validated across ALL versions")
    if not hits:
        print("  (none)")
    for (rule, dialect), n in hits.most_common():
        print(f"  {rule:>8} {dialect:>10}  -> {n} entries")
        for base, name, sample in detail[(rule, dialect)][:3]:
            print(f"        e.g. {base}:{name}  {sample}")
    print()
    print(f"combos with >=1 full-version match: {len(hits)}")
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())

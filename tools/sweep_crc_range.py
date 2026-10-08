#!/usr/bin/env python3
"""Broad CRC-range sweep: per-entry (start, end) enumeration.

Step 3 of docs/C0A_EXPLOITATION.md. The structured rule search
(tools/find_crc_range.py) found nothing; this sweeps a much larger space:

  * start anchors: 0x00, 0x10, 0x20, 0x24, 0x28, 0x2c, 0x30, e.offset-0x20,
    e.offset, plus the entry header position
  * end anchors:   e.offset + e.size, +0x20 (header of the next entry), the
    next entry's offset, the sector end (next 0x1000), the member end, and
    e.offset + e.size minus small deltas
  * dialects: zlib (reflected), jamcrc, direct (poly 0x04C11DB7, init ~0, with
    and without final xor), and 16-bit hi/lo truncations

For each (start, end, dialect) we record whether it reproduces the stored CRC
(a) for at least one entry in one version, and (b) for the same entry across
all three versions (the strong signal).

Usage:
    python3 tools/sweep_crc_range.py [--member C1C ...] [--versions 180 181 182]
"""

from __future__ import annotations

import argparse
import sys
import zlib
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]

_DIRECT_TABLE = []
for _i in range(256):
    _c = _i << 24
    for _ in range(8):
        _c = ((_c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if _c & 0x80000000 else (_c << 1) & 0xFFFFFFFF
    _DIRECT_TABLE.append(_c)


def crc_direct(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _DIRECT_TABLE[((crc >> 24) ^ b) & 0xFF]
    return crc


def dialects(data: bytes) -> dict[str, int]:
    z = zlib.crc32(data) & 0xFFFFFFFF
    out = {
        "zlib": z, "jamcrc": z ^ 0xFFFFFFFF,
        "zlib_lo16": z & 0xFFFF, "zlib_hi16": z >> 16,
    }
    # the direct (non-reflected) CRC is pure-Python and dominates runtime on
    # large spans; only compute it when the span is small enough to matter.
    if len(data) <= 0x40000:
        d = crc_direct(data)
        out["direct"] = d
        out["direct_xor"] = d ^ 0xFFFFFFFF
    return out


def entry_windows(data: bytes, entries, i: int):
    """Candidate (start, end) pairs for entry i, clamped to the member."""
    e = entries[i]
    n = len(data)
    e_end = min(e.offset + e.size, n)
    nxt = entries[i + 1].offset if i + 1 < len(entries) else n
    sector_end = min(e.offset + 0x1000, n)
    starts = {0, 0x10, 0x20, 0x24, 0x28, 0x2C, 0x30,
              e.offset - 0x20, e.offset, 0x30 + i * 0x20}
    ends = {e_end, e_end + 0x20, nxt, sector_end,
            e_end - 0x10, e_end - 0x8, e_end - 0x4, e_end - 0x2, e_end - 0x1}
    # member-end ranges are only interesting for the LAST entry (otherwise the
    # span covers unrelated payloads and costs megabytes per computation), and
    # a per-entry check field cannot plausibly cover >2 MiB anyway.
    if i == len(entries) - 1:
        ends.add(n)
    for s in sorted(starts):
        if s < 0 or s > 0x10000:  # starts near the member head only
            continue
        for t in sorted(ends):
            if t <= s or t > n:
                continue
            if t - s > 2 * 1024 * 1024:
                continue
            yield s, t


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--versions", nargs="+", default=["180", "181", "182"])
    ap.add_argument("--member", nargs="+", default=["C1C", "C0C", "C1A"])
    args = ap.parse_args(argv)

    versions = args.versions
    members = args.member

    by_key: dict[tuple[str, str], dict[str, tuple]] = defaultdict(dict)
    for v in versions:
        raw = fw.load_container(REPO / f"mc101_sys_v{v}.zip")
        for m in fw.parse_tar(raw):
            base = m.name.split("/")[-1]
            if not any(mem in base for mem in members) or not fw.is_qspi(m.data):
                continue
            img = fw.parse_qspi(m.data)
            for idx, e in enumerate(img.entries):
                by_key[(base, e.name.strip())][v] = (m.data, img.entries, idx)

    common = {k: d for k, d in by_key.items() if all(v in d for v in versions)}

    single_hits: dict[tuple, int] = defaultdict(int)
    cross_ok: dict[tuple, list] = defaultdict(list)

    for (base, name), per_ver in common.items():
        per_version_rules: dict = defaultdict(dict)
        for v in versions:
            data, entries, idx = per_ver[v]
            for (s, t) in entry_windows(data, entries, idx):
                got = dialects(data[s:t])
                for dname, val in got.items():
                    if val == entries[idx].crc:
                        single_hits[(dname,)] += 1
                        per_version_rules[(s, t, dname)][v] = True
        for rule, vset in per_version_rules.items():
            if all(v in vset for v in versions):
                cross_ok[rule].append((base, name))

    print(f"versions: {', '.join(versions)}  members: {', '.join(members)}")
    print(f"entries present in every version: {len(common)}")
    print()
    print(f"raw single (dialect) reproductions anywhere: {dict(single_hits)}")
    print()
    print("rules reproducing the SAME entry in ALL versions:")
    if not cross_ok:
        print("  (none)")
    for rule, hits in sorted(cross_ok.items(), key=lambda kv: -len(kv[1])):
        print(f"  (start={rule[0]:#x}, end={rule[1]:#x}, {rule[2]}) -> {len(hits)} entries")
        for base, name in hits[:5]:
            print(f"        {base}:{name}")
    return 0 if cross_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

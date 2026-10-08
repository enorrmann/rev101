#!/usr/bin/env python3
"""Build the ECB-anchor known-plaintext corpus from the C0A bodies (§1 of
docs/C0A_EXPLOITATION.md).

FINDINGS.md §4 established by hand that `0xa0000-0xb5000` within the C0A body
contains thousands of runs of one fixed 8-byte value repeated every 8 bytes,
always starting on 8-byte boundaries — the signature of `E_K(0x00…00)` anchors
of an 8-byte (64-bit) block cipher in ECB mode. Those anchors are the only
concrete ciphertext structure available, and they are stable in value across
versions while shifting in position where the plaintext shifted.

This tool automates the manual step:

  * `anchors`  — values repeating >= min_repeats times on aligned boundaries,
                 reported per version as (value -> [offsets, ...]).
  * `diff`     — for two versions, pair anchors by value and report how their
                 offset sets relate (a stable anchor that merely shifted).

Outputs a CSV (`--csv PATH`) of
    value,count_v180,count_v181,count_v182,first_v180,first_v181,first_v182
which *is* the reusable known-plaintext corpus.

Usage:
    python3 tools/find_anchors.py --region 0xa0000:0xb5000 --csv anchors.csv
    python3 tools/find_anchors.py --diff 180 181
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
C0A = "RPG69_C0A_up.bin"


def load_body(version: str) -> bytes:
    raw = fw.load_container(REPO / f"mc101_sys_v{version}.zip")
    for m in fw.parse_tar(raw):
        if C0A in m.name:
            return m.data[fw.C0A_HEADER_SIZE:]
    raise SystemExit(f"C0A member not found in v{version}")


def find_anchors(body: bytes, region: tuple[int, int] | None,
                 block: int, min_repeats: int) -> dict[bytes, list[int]]:
    if region is None:
        lo, hi = 0, len(body)
    else:
        lo, hi = region
        hi = min(hi, len(body))
    hits: dict[bytes, list[int]] = defaultdict(list)
    start = lo - (lo % block)
    for off in range(start, hi - block, block):
        hits[body[off:off + block]].append(off)
    return {v: offs for v, offs in hits.items() if len(offs) >= min_repeats}


def parse_region(s: str | None):
    if not s:
        return None
    lo, hi = s.split(":")
    return int(lo, 0), int(hi, 0)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--versions", nargs="+", default=["180", "181", "182"])
    ap.add_argument("--region", default="0xa0000:0xb5000",
                    help="start:end hex; empty string for the whole body")
    ap.add_argument("--block", type=int, default=8)
    ap.add_argument("--min-repeats", type=int, default=3)
    ap.add_argument("--csv", default=None, help="write the corpus CSV here")
    ap.add_argument("--diff", nargs=2, metavar=("VA", "VB"),
                    help="pair anchors between two versions by value")
    args = ap.parse_args(argv)

    region = parse_region(args.region)
    bodies = {v: load_body(v) for v in args.versions}
    anchors = {v: find_anchors(bodies[v], region, args.block, args.min_repeats)
               for v in args.versions}

    print(f"region: {args.region or 'whole body'}  block={args.block} "
          f"min_repeats={args.min_repeats}")
    for v in args.versions:
        runs = sum(len(o) for o in anchors[v].values())
        print(f"  v{v}: {len(anchors[v]):,} distinct anchor values, "
              f"{runs:,} aligned repeat occurrences")
    print()

    if args.diff:
        va, vb = args.diff
        if va not in anchors or vb not in anchors:
            print("error: --diff versions must be in --versions", file=sys.stderr)
            return 2
        a, b = anchors[va], anchors[vb]
        shared = set(a) & set(b)
        print(f"anchors shared by value v{va} ∩ v{vb}: {len(shared)}")
        # position relationship: for shared values, compare first offsets
        deltas = defaultdict(int)
        for v in shared:
            deltas[b[v][0] - a[v][0]] += 1
        top = sorted(deltas.items(), key=lambda kv: -kv[1])[:8]
        print(f"  first-offset delta (v{vb} - v{va}) distribution (top):")
        for d, n in top:
            print(f"    {d:+#x}  x{n}")
        print()

    if args.csv:
        all_vals = set()
        for v in args.versions:
            all_vals |= set(anchors[v])
        with open(args.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["value_hex"] + [f"count_v{v}" for v in args.versions]
                       + [f"first_v{v}" for v in args.versions])
            for val in sorted(all_vals):
                row = [val.hex()]
                row += [len(anchors[v].get(val, [])) for v in args.versions]
                row += [(anchors[v][val][0] if val in anchors[v] else "")
                        for v in args.versions]
                w.writerow(row)
        print(f"wrote corpus CSV: {args.csv} ({len(all_vals)} anchor values)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

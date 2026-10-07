#!/usr/bin/env python3
"""Extract and rebuild Roland MC-101 (RPG69) firmware containers.

Usage:
  python3 tools/extract.py --version 182 --out firmware/raw
  python3 tools/extract.py --all --out firmware/raw
  python3 tools/extract.py --version 182 --repack-check

The `--repack-check` mode is the important one: it extracts a container and
then rebuilds it from the parsed structures, asserting the result is
byte-identical to the input.  A byte-exact rebuild proves that any difference
we later introduce in a modified image is exactly the change we intended.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def do_extract(version: str, outdir: Path, verify: bool) -> int:
    src = REPO / f"mc101_sys_v{version}.zip"
    if not src.exists():
        print(f"error: {src} not found", file=sys.stderr)
        return 1

    raw = fw.load_container(src)
    members = fw.parse_tar(raw)
    dest = outdir / f"v{version}"
    dest.mkdir(parents=True, exist_ok=True)

    print(f"=== v{version}: {src.name} -> {dest} ===")
    rebuilt_members: list[fw.TarMember] = []

    for m in members:
        # tar member names come from the container, so sanitize before using
        # one as a filename (basename alone still allows `..\x` on Windows)
        base = fw.safe_entry_name(m.name.split("/")[-1])
        target = fw.resolve_within(dest, base)
        target.write_bytes(m.data)
        print(f"  {base:24s} {len(m.data):>12,} B  sha256={sha256(m.data)[:16]}")

        data = m.data
        if fw.is_qspi(data):
            img = fw.parse_qspi(data)
            sub = dest / (base.replace(".bin", "") + "_entries")
            sub.mkdir(exist_ok=True)
            print(f"      QSPI: {len(img.entries)} entries -> {sub.name}/")
            for i, e in enumerate(img.entries):
                # entry names come from the firmware image, so sanitize before
                # using one as a filename (see fw.safe_entry_name)
                safe = fw.safe_entry_name(e.name, i)
                target = fw.resolve_within(sub, safe)
                target.write_bytes(e.data)
                plain = "plaintext" if _looks_plain(e.data) else "high-entropy"
                print(f"        {safe:24s} {e.size:>12,} B  {plain}")
            data = fw.build_qspi(img)
        elif data[:9].rstrip(b"\x00") == b"App1_Main":
            h = fw.parse_app1_header(data)
            print(
                f"      App1: name={h.name} ver={h.version} date={h.date} "
                f"load={h.load_addr:#x} digest={h.digest:#010x}"
            )

        rebuilt_members.append(
            fw.TarMember(
                name=m.name,
                size=len(data),
                offset=0,
                data=data,
                mode=m.mode,
                uid=m.uid,
                gid=m.gid,
                mtime=m.mtime,
                uname=m.uname,
                gname=m.gname,
            )
        )

    if verify:
        rebuilt = fw.build_tar(rebuilt_members)
        if rebuilt == raw:
            print("  REPACK CHECK: byte-identical  OK")
        else:
            n = min(len(rebuilt), len(raw))
            pos = next((i for i in range(n) if rebuilt[i] != raw[i]), None)
            where = f"{pos:#x}" if pos is not None else "length mismatch"
            print(f"  REPACK CHECK: FAILED at {where}", file=sys.stderr)
            return 2

    return 0


def _looks_plain(data: bytes, limit: int = 65536) -> bool:
    import collections
    import math

    b = data[:limit]
    if not b:
        return False
    c = collections.Counter(b)
    n = len(b)
    h = -sum(v / n * math.log2(v / n) for v in c.values())
    return h < 7.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="append", default=[],
                    help="firmware version digits, e.g. 182 (repeatable)")
    ap.add_argument("--all", action="store_true", help="process v180, v181, v182")
    ap.add_argument("--out", default="firmware/raw", help="output directory")
    ap.add_argument("--repack-check", action="store_true",
                    help="verify a byte-exact rebuild after extracting")
    args = ap.parse_args()

    versions = list(args.version)
    if args.all or not versions:
        versions = ["180", "181", "182"]

    outdir = Path(args.out)
    if not outdir.is_absolute():
        outdir = REPO / outdir

    rc = 0
    for v in versions:
        rc |= do_extract(v, outdir, args.repack_check)
        print()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

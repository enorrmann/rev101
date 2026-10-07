#!/usr/bin/env python3
"""Build a modified MC-101 firmware image by patching QSPI entry payloads.

This is the mechanism layer: it replaces whole entry payloads inside a QSPI
member and repacks the tar container, preserving every metadata field so the
result is a structurally valid update image.

Usage:
  python3 tools/patch.py --base mc101_sys_v182.zip --out build/MC101_UPA_up.bin \\
      --replace RPG69_C1A_up.bin:sdram1.bin:firmware/decoded/sdram1_patched.bin

  python3 tools/patch.py --base mc101_sys_v182.zip --out build/candidate.bin \\
      --replace-in-place RPG69_C1C_up.bin:qspi_ver_def.h:firmware/decoded/qspi_ver_def.h

Safety: this never touches hardware. It writes an image file and reports a
diff summary versus the base so you can see exactly what changed.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def parse_replace(spec: str) -> tuple[str, str, Path]:
    """Parse 'MEMBER:ENTRY:FILE'."""
    parts = spec.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"--replace expects MEMBER:ENTRY:FILE, got {spec!r}"
        )
    return parts[0], parts[1], Path(parts[2])


def build(base: Path, replacements: list[tuple[str, str, Path]],
          out: Path) -> int:
    raw = fw.load_container(base)
    members = fw.parse_tar(raw)

    applied: list[str] = []
    rebuilt: list[fw.TarMember] = []

    for m in members:
        base_name = m.name.split("/")[-1]
        data = m.data

        if fw.is_qspi(data):
            img = fw.parse_qspi(data)
            for member_key, entry_name, src in replacements:
                if member_key not in base_name:
                    continue
                hit = False
                for e in img.entries:
                    if e.name.strip() == entry_name:
                        if not src.exists():
                            print(f"error: {src} not found", file=sys.stderr)
                            return 1
                        new = src.read_bytes()
                        print(
                            f"  replace {base_name}:{entry_name} "
                            f"{e.size:,} B -> {len(new):,} B  (sha {sha(e.data)} -> {sha(new)})"
                        )
                        e.data = new
                        e.size = len(new)
                        hit = True
                        applied.append(f"{base_name}:{entry_name}")
                if not hit:
                    print(
                        f"error: entry {entry_name!r} not found in {base_name}",
                        file=sys.stderr,
                    )
                    return 1
            data = fw.build_qspi(img)

        rebuilt.append(
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

    if len(applied) != len(replacements):
        for member_key, entry_name, _ in replacements:
            key = f"{member_key}:{entry_name}"
            if not any(key in a for a in applied):
                print(f"error: replacement {key} was never applied", file=sys.stderr)
                return 1

    image = fw.build_tar(rebuilt)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(image)

    print(f"\nwrote {out}  ({len(image):,} B, sha256 {hashlib.sha256(image).hexdigest()[:32]})")

    # report the diff versus the base so the change is auditable
    n = min(len(image), len(raw))
    diffs = [i for i in range(n) if image[i] != raw[i]]
    print(f"diff vs base: {len(diffs):,} bytes differ"
          + (f", first at {diffs[0]:#x}" if diffs else "")
          + (f", length {len(raw):,} -> {len(image):,}" if len(raw) != len(image) else ""))
    if not diffs and len(raw) == len(image):
        print("  (identical to base - no change was made)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--base", required=True, help="base .zip or MC101_UPA_up.bin")
    ap.add_argument("--out", required=True, help="output image path")
    ap.add_argument(
        "--replace",
        action="append",
        default=[],
        metavar="MEMBER:ENTRY:FILE",
        help="replace a QSPI entry payload (repeatable), "
        "e.g. RPG69_C1A_up.bin:sdram1.bin:new_sdram1.bin",
    )
    args = ap.parse_args()

    if not args.replace:
        print("error: give at least one --replace", file=sys.stderr)
        return 2

    base = Path(args.base)
    if not base.is_absolute():
        base = REPO / base
    if not base.exists():
        print(f"error: {base} not found", file=sys.stderr)
        return 1

    reps = [parse_replace(s) for s in args.replace]
    print(f"base: {base.name}")
    for member_key, entry_name, src in reps:
        print(f"  will replace {member_key}:{entry_name} <- {src}")
    print()

    return build(base, reps, Path(args.out))


if __name__ == "__main__":
    raise SystemExit(main())

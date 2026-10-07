#!/usr/bin/env python3
"""Build a candidate modified firmware image for eventual on-hardware testing.

The modification applied is deliberately minimal and reversible: a same-size
edit of the plaintext `qspi_ver_def.h` entry inside the `C1C` (secondary MCU)
image.  It changes the PRM_VER digits so the change is auditable, keeps every
container offset valid, and touches nothing whose format we do not understand.

Nothing here writes to hardware.  The output is an image file plus a diff
report; flashing it is your decision.

  output: build/MC101_UPA_up.bin
  diff:   expected to be exactly 3 bytes versus the base image
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
BASE = REPO / "mc101_sys_v182.zip"
OUT_DIR = REPO / "build"
OUT_IMAGE = OUT_DIR / "MC101_UPA_up.bin"

TARGET_MEMBER = "RPG69_C1C_up.bin"
TARGET_ENTRY = "qspi_ver_def.h"
OLD = b"0.039"
NEW = b"9.999"


def main() -> int:
    if not BASE.exists():
        print(f"error: {BASE.name} not found", file=sys.stderr)
        return 1

    original = fw.load_container(BASE)
    members = fw.parse_tar(original)

    print(f"base: {BASE.name} ({len(original):,} B)")
    print(f"edit: {TARGET_MEMBER}:{TARGET_ENTRY}  {OLD.decode()} -> {NEW.decode()}")

    out_members: list[fw.TarMember] = []
    edited = 0

    for m in members:
        data = m.data
        base_name = m.name.split("/")[-1]

        if fw.is_qspi(data) and TARGET_MEMBER in base_name:
            img = fw.parse_qspi(data)
            for e in img.entries:
                if e.name.strip() != TARGET_ENTRY:
                    continue
                if OLD not in e.data:
                    print(f"error: pattern {OLD!r} not found in entry", file=sys.stderr)
                    return 1
                new_payload = e.data.replace(OLD, NEW, 1)
                if len(new_payload) != len(e.data):
                    print("error: replacement changed length", file=sys.stderr)
                    return 1
                print(f"  entry {e.size:,} B, {sum(1 for a,b in zip(e.data,new_payload) if a!=b)} bytes edited")
                e.data = new_payload
                edited += 1
            data = fw.build_qspi(img)

        out_members.append(
            fw.TarMember(
                name=m.name, size=len(data), offset=0, data=data,
                mode=m.mode, uid=m.uid, gid=m.gid, mtime=m.mtime,
                uname=m.uname, gname=m.gname,
            )
        )

    if edited != 1:
        print(f"error: expected to edit exactly 1 entry, edited {edited}", file=sys.stderr)
        return 1

    image = fw.build_tar(out_members)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_IMAGE.write_bytes(image)

    diffs = [i for i in range(min(len(image), len(original))) if image[i] != original[i]]
    print()
    print(f"wrote {OUT_IMAGE.relative_to(REPO)}")
    print(f"  size   : {len(image):,} B (base {len(original):,} B)")
    print(f"  sha256 : {hashlib.sha256(image).hexdigest()}")
    print(f"  diff   : {len(diffs)} bytes"
          + (f", first at {diffs[0]:#x}" if diffs else ""))
    if len(diffs) != 3:
        print(f"  WARNING: expected exactly 3 changed bytes, saw {len(diffs)}", file=sys.stderr)
        return 2

    print()
    print("This image is structurally valid and re-parses cleanly.")
    print("It has NOT been tested on hardware. Flashing is your decision.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

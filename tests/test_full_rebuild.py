#!/usr/bin/env python3
"""End-to-end test: a full container rebuild must reproduce the original byte-for-byte.

This is the acceptance test that matters for shipping a modified image: if
`extract -> modify -> repack` is byte-exact when nothing is modified, then any
diff in the output is provably the change we intended.

Also verifies the structural facts we rely on when planning a patch:
  * C0A payload is high-entropy and only partly compressible => it cannot be
    edited in place (see FINDINGS.md §4; entropy alone is not proof of
    encryption, so the test uses compressibility).
  * C1A/C1C entries (idm1.bin, sdram1.bin) are plaintext ARM => editable.

Run:  python3 tests/test_full_rebuild.py
"""

from __future__ import annotations

import collections
import hashlib
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
VERSIONS = ["v180", "v181", "v182"]


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def full_rebuild(path: Path) -> tuple[bytes, bytes]:
    """Return (original_container, rebuilt_container) using the public API."""
    raw = fw.load_container(path)
    members = fw.parse_tar(raw)

    rebuilt_members: list[fw.TarMember] = []
    for m in members:
        data = m.data
        if fw.is_qspi(data):
            img = fw.parse_qspi(data)
            data = fw.build_qspi(img)
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

    return raw, fw.build_tar(rebuilt_members)


def main() -> int:
    failures = 0
    checks = 0

    print("=" * 72)
    print("Full container rebuild (byte-exact acceptance test)")
    print("=" * 72)
    for v in VERSIONS:
        p = REPO / f"mc101_sys_{v}.zip"
        if not p.exists():
            print(f"SKIP  {p.name} not found")
            continue
        original, rebuilt = full_rebuild(p)
        checks += 1
        ok = original == rebuilt
        if ok:
            print(f"PASS  {p.name}: rebuild is byte-identical ({len(original):,} B)")
        else:
            failures += 1
            n = min(len(original), len(rebuilt))
            d = next((i for i in range(n) if original[i] != rebuilt[i]), None)
            print(f"FAIL  {p.name}: differs at {d:#x}" if d is not None else
                  f"FAIL  {p.name}: length {len(original):,} vs {len(rebuilt):,}")

    print()
    print("=" * 72)
    print("Structural facts that gate the patch strategy")
    print("=" * 72)

    p = REPO / "mc101_sys_v182.zip"
    members = fw.open_firmware(p)
    for m in members:
        base = m.name.split("/")[-1]
        if base.endswith("C0A_up.bin"):
            body = m.data[fw.C0A_HEADER_SIZE :]
            h = entropy(body)
            import zlib

            # NOTE: entropy alone is a misleading test here.  The C0A payload
            # has entropy 7.888 and only 256 distinct byte values, which looks
            # "encrypted" at a glance -- but zlib compresses it to ~73% of its
            # size (random data would compress to ~100%).  So C0A is COMPRESSED,
            # and we cannot yet tell whether it is also encrypted underneath.
            # The honest test is compressibility, not entropy.
            ratio = len(zlib.compress(body, 6)) / len(body)
            checks += 1
            compressed = ratio < 0.97
            if not compressed:
                failures += 1
            print(
                f"{'PASS' if compressed else 'FAIL'}  {base}: payload entropy {h:.3f}, "
                f"zlib ratio {ratio:.3f} -> {'COMPRESSED (not raw ciphertext)' if compressed else 'incompressible'}"
            )
            print(
                f"        => C0A is compressed; encryption status undetermined "
                f"from this test alone"
            )
        elif fw.is_qspi(m.data):
            img = fw.parse_qspi(m.data)
            plain = [e.name.strip() for e in img.entries if entropy(e.data[:65536]) < 7.0]
            checks += 1
            ok = len(plain) > 0
            if not ok:
                failures += 1
            print(
                f"{'PASS' if ok else 'FAIL'}  {base}: {len(plain)}/{len(img.entries)} "
                f"entries editable in place"
            )
            for e in img.entries:
                if e.name.strip() in ("idm1.bin", "sdram1.bin"):
                    h = entropy(e.data[:65536])
                    checks += 1
                    ok = h < 7.0
                    if not ok:
                        failures += 1
                    print(
                        f"{'PASS' if ok else 'FAIL'}    {e.name.strip():14s} "
                        f"entropy={h:.3f} size={e.size:>10,} "
                        f"({'plaintext ARM' if ok else 'encrypted'})"
                    )

    print()
    print(f"{checks - failures}/{checks} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

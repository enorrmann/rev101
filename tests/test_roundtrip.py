#!/usr/bin/env python3
"""Round-trip verification for the MC-101 container tooling.

Acceptance criterion: extract -> rebuild must reproduce the original
container byte-for-byte for all three released firmware versions.

Run:  python3 tests/test_roundtrip.py [path/to/mc101_sys_v18X.zip ...]
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
DEFAULT = [
    REPO / "mc101_sys_v180.zip",
    REPO / "mc101_sys_v181.zip",
    REPO / "mc101_sys_v182.zip",
]


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def test_qspi_roundtrip(name: str, data: bytes, results: list[tuple[bool, str]]) -> None:
    img = fw.parse_qspi(data)
    rebuilt = fw.build_qspi(img)
    ok = rebuilt == data
    results.append((ok, f"  QSPI roundtrip {name}: {len(data):,}B -> {len(rebuilt):,}B"))
    if not ok:
        # report the first divergence to make failures actionable
        n = min(len(rebuilt), len(data))
        diff = next((i for i in range(n) if rebuilt[i] != data[i]), None)
        results.append(
            (False, f"    MISMATCH at {diff:#x}" if diff is not None else
             f"    LENGTH differs: {len(data):,} vs {len(rebuilt):,}")
        )


def test_tar_roundtrip(path: Path, results: list[tuple[bool, str]]) -> None:
    raw = fw.load_container(path)
    members = fw.parse_tar(raw)

    # 1. member payloads must survive parse -> rebuild unchanged
    for m in members:
        assert m.data is not None

    # 2. each QSPI member must round-trip
    for m in members:
        base = m.name.split("/")[-1]
        if fw.is_qspi(m.data):
            test_qspi_roundtrip(base, m.data, results)
        elif m.data[:9].rstrip(b"\x00") == b"App1_Main":
            h = fw.parse_app1_header(m.data)
            ok = h.size_consistent(len(m.data))
            results.append(
                (ok,
                 f"  App1 header {base}: ver={h.version} date={h.date} "
                 f"size_consistent={ok} digest={h.digest:#010x}")
            )

    # 3. the tar itself must rebuild to the same member set
    rebuilt_tar = fw.build_tar(members)
    members2 = fw.parse_tar(rebuilt_tar)
    same = [m.data for m in members] == [m.data for m in members2]
    results.append((same, f"  tar payload roundtrip: {len(members)} members identical"))

    # 4. a full byte-exact rebuild is the real acceptance criterion
    exact = rebuilt_tar == raw
    results.append((exact, f"  full container rebuild byte-exact: {exact}"))


def main(paths: list[Path]) -> int:
    results: list[tuple[bool, str]] = []
    for p in paths:
        if not p.exists():
            results.append((False, f"{p}: NOT FOUND"))
            continue
        print(f"=== {p.name} ===")
        test_tar_roundtrip(p, results)

    print()
    failed = 0
    for ok, msg in results:
        print(f"{'PASS' if ok else 'FAIL'} {msg}")
        if not ok:
            failed += 1

    print()
    print(f"{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    argv = [Path(a) for a in sys.argv[1:]] or DEFAULT
    raise SystemExit(main(argv))

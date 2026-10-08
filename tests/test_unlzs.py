#!/usr/bin/env python3
"""Verify the 4-bit-framed `init.lzs` unframing (tools/unlzs.py).

The discovery this test pins down: `init.lzs` is not a compressed blob — its
payload is recovered by dropping every byte whose low nibble is `f`, which
leaves the readable init-data stream.  We verify the two properties that were
measured by hand while reverse engineering:

1. A synthetic framed stream round-trips: markers are separated from payload
   bytes exactly.
2. The real v1.82 `init.lzs` extraction has the measured marker fraction and,
   crucially, contains the factory drum-kit name "TR-909 Kick 1" in its
   decoded payload (the smoking gun that the unframing is the real codec rule,
   not a statistical artefact).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import unlzs  # noqa: E402


def framed_roundtrip():
    # payload bytes with two markers interleaved: 0x2f and 0xff
    framed = bytes([0x41, 0x2F, 0x42, 0xFF, 0x43])
    payload, markers = unlzs.unframe(framed)
    assert payload == bytes([0x41, 0x42, 0x43]), payload
    assert markers == bytes([0x2, 0xF]), markers


def real_file_properties():
    repo = Path(__file__).resolve().parents[1]
    src = repo / "firmware/raw/v182/RPG69_C0C_up_entries/init.lzs"
    assert src.exists(), f"run `make extract-all` first ({src} missing)"
    data = src.read_bytes()
    payload, markers = unlzs.unframe(data[0x40:])
    # measured on all three releases: 48.5 % markers, 498,599 B payload
    assert len(markers) == 470_382, len(markers)
    assert len(payload) == 498_599, len(payload)
    assert b"TR-909 Kick 1" in payload, "decoded payload must contain the drum kit name"


def main() -> int:
    checks = 0
    framed_roundtrip()
    checks += 1
    print("PASS  synthetic framed stream round-trips")
    real_file_properties()
    checks += 1
    print("PASS  real init.lzs: 470,382 markers / 498,599 B payload, 'TR-909 Kick 1' found")
    print()
    print(f"{checks}/{checks} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

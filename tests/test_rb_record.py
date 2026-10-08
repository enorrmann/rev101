#!/usr/bin/env python3
"""Verify the CONFIRMED plaintext record-container schema (tools/rb_record.py).

Pins the one schema that is byte-verified end to end in this workspace:
the `C0C`/`C1C` record-array entries (`kit/tone/inst_pcmx_*`, `spf_muse_*`,
`wpf_muse_*`).  `init.lzs` is explicitly NOT covered here (it is a `PRJ5`
project container whose field schema is unresolved).

Checks (all derived from measurement, not assumption):
* 0x20 zero prefix; type word; payload = count*record_size + 12;
  names are 16-byte fields starting at file offset 0x3c on the record pitch.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import rb_record  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def check(rel: str, type_word: int, count: int, record_size: int,
          first_name: bytes) -> None:
    data = (REPO / rel).read_bytes()
    rc = rb_record.parse(data)
    ok, msg = rc.verify(len(data))
    assert ok, f"{rel}: verify failed ({msg})"
    assert rc.type_word == type_word, (rel, hex(rc.type_word))
    assert rc.count == count, (rel, rc.count)
    assert rc.record_size == record_size, (rel, rc.record_size)
    assert rc.names[0].encode("latin-1") == first_name, (rel, rc.names[0])


def main() -> int:
    check("firmware/raw/v182/RPG69_C0C_up_entries/kit_pcmx_cmn.bin",
          0x00120005, 74, 3328, b"Standard Kit    ")
    check("firmware/raw/v182/RPG69_C0C_up_entries/tone_pcmx_cmn.bi",
          0x00140004, 837, 1432, b"Piano 1         ")
    check("firmware/raw/v182/RPG69_C0C_up_entries/inst_pcmx_cmn.bi",
          0x00120003, 711, 216, b"Off             ")
    check("firmware/raw/v182/RPG69_C1C_up_entries/spf_muse_rpg68.b",
          0x00200002, 850, 272, b"Ult.P*mp A L\x00\x00\x00\x00")
    print("PASS  record-container schema: kit/tone/inst/spf headers byte-exact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

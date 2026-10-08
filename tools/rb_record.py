#!/usr/bin/env python3
"""Parse the *confirmed* Roland MC-101 (RPG69) plaintext record-container.

This is the one schema in this workspace that is byte-verified end to end.
It applies to the plaintext `C0C`/`C1C` entries such as

    kit_pcmx_cmn.bin   tone_pcmx_cmn.bi   inst_pcmx_cmn.bi
    spf_muse_rpg68.b   wpf_muse_*.b       …

It does NOT apply to `init.lzs` (a `PRJ5` project container whose field-level
schema is still unresolved; see docs/FINDINGS.md).

Confirmed layout (all little-endian):

    0x00  0x20 zero bytes
    0x20  u32  type word        (e.g. 0x00120005 for kits)
    0x24  u32  name length      (16: names are 16-byte space-padded fields)
    0x28  u32  payload bytes    (record count * record size + 12)
    0x2c  u32  constant 0x1d (29)
    0x30  u32  record count
    0x34  u32  array-header size (12)
    0x38  u32  record size
    0x3c       records begin; each record starts with its 16-byte name
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RecordContainer:
    type_word: int
    name_len: int
    payload_len: int
    const29: int
    count: int
    table_header: int
    record_size: int
    names: list[str]

    def verify(self, raw_len: int) -> tuple[bool, str]:
        expected_payload = self.count * self.record_size + self.table_header
        ok_payload = self.payload_len == expected_payload
        # The file is the 0x20 prefix + payload; Roland's entry-size field may
        # under-report a few tail bytes as encoded in the image file, so allow
        # a small negative delta (observed: kit file is 12 B short of 74 full
        # records — the last record's tail is truncated).
        declared_file = 0x20 + self.payload_len
        ok_file = raw_len <= declared_file and declared_file - raw_len <= 0x1000
        msg = (f"payload {self.payload_len:#x} vs count*size+hdr "
               f"{expected_payload:#x}; file {raw_len:#x} vs 0x20+payload "
               f"{declared_file:#x}")
        return (ok_payload and ok_file), msg


def parse(data: bytes) -> RecordContainer:
    if len(data) < 0x40 or data[:0x20] != b"\x00" * 0x20:
        raise ValueError("not a record container (missing 0x20 zero prefix)")
    type_word, name_len = struct.unpack_from("<II", data, 0x20)
    payload, const29 = struct.unpack_from("<II", data, 0x28)
    count, table_header = struct.unpack_from("<II", data, 0x30)
    record_size = struct.unpack_from("<I", data, 0x38)[0]

    names = []
    for i in range(count):
        off = 0x3C + i * record_size
        if off + name_len > len(data):
            break
        names.append(data[off : off + name_len].decode("latin-1"))

    return RecordContainer(type_word, name_len, payload, const29, count,
                           table_header, record_size, names)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="path to a plaintext record entry")
    ap.add_argument("--names", action="store_true", help="print every record name")
    args = ap.parse_args(argv)

    p = Path(args.path)
    if not p.exists():
        print(f"error: {p} not found", file=sys.stderr)
        return 1

    data = p.read_bytes()
    try:
        rc = parse(data)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    ok, msg = rc.verify(len(data))
    print(f"file           {p}")
    print(f"type word      {rc.type_word:#010x}")
    print(f"name length    {rc.name_len}")
    print(f"payload bytes  {rc.payload_len}")
    print(f"record count   {rc.count}")
    print(f"table header   {rc.table_header}")
    print(f"record size    {rc.record_size}")
    print(f"verify         {'OK' if ok else 'MISMATCH'}  ({msg})")
    if args.names:
        for i, n in enumerate(rc.names):
            print(f"  [{i:4d}] {n!r}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

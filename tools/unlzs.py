#!/usr/bin/env python3
"""Unpack the Roland MC-101 (RPG69) `init.lzs` nibble-framed stream.

Background
----------
`init.lzs` (the C0C entry that holds the application's initial data) is not
compressed in the usual sense: it is a *4-bit-framed* serialisation, in which
the actual 8-bit data bytes are interleaved with marker bytes whose low nibble
is `f` (0x0f .. 0xff).  The marker bytes carry a 4-bit control/extension in
their HIGH nibble, so the full logical stream is a sequence of

    [8-bit data byte]  optionally followed by  [4-bit marker nibble]

Drop the markers and you get the readable payload: byte-verified strings are
the header tags `PRJ5`/`aMC7`/`STP`, `INIT`/`InitT`, and the drum-kit fragment
names `TR-909 Kick 1`, `Rimsh...t`, `Clap 2`, `MidG2M0`, `707 Tamb` (see docs
for the byte-verified list — most other short "printable" runs are marker/ASCII
coincidences in the parameter tables, NOT names).

The marker's 4 bits are recovered into a parallel stream (`markers`), because
they are almost certainly meaningful (field-type/continuation codes), but their
exact semantics are not yet known.

The reconstruction below is lossless in one direction (marker drop), but note
that data bytes which themselves end in `f` are not distinguishable from
markers without the encoder's full framing rules; the recovered payload is
therefore the *filtered* view, which is nonetheless fully readable for the
name tables.

Usage:
    python3 tools/unlzs.py [path-to-init.lzs] [--strings | --hex]

Outputs (same base, added suffix):
    <base>.decoded      the filtered 8-bit payload
    <base>.markers      the orphaned 4-bit marker values, one byte each
    <base>.strings      printable runs (requires --strings, or always printed)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


HEADER_SIZE = 0x40


def unframe(data: bytes) -> tuple[bytes, bytes]:
    """Return (payload, markers) from a nibble-framed stream.

    Every byte whose low nibble is `f` is treated as a marker; its high nibble
    is appended to `markers`.  Every other byte is appended to the payload in
    stream order.
    """
    payload = bytearray()
    markers = bytearray()
    for b in data:
        if (b & 0x0F) == 0x0F:
            markers.append(b >> 4)
        else:
            payload.append(b)
    return bytes(payload), bytes(markers)


def printable_runs(data: bytes, min_len: int = 5) -> list[tuple[int, str]]:
    runs = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        runs.append((m.start(), m.group().decode("latin-1")))
    return runs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default="firmware/raw/v182/RPG69_C0C_up_entries/init.lzs",
                    help="path to an init.lzs extraction (default: %(default)s)")
    ap.add_argument("--skip-header", action="store_true",
                    help="treat the whole file as framed data (default skips the first 0x40 bytes)")
    ap.add_argument("--strings", action="store_true",
                    help="print printable runs from the decoded payload")
    ap.add_argument("--min-len", type=int, default=5,
                    help="minimum printable run length for --strings (default 5)")
    args = ap.parse_args(argv)

    src = Path(args.path)
    if not src.exists():
        print(f"error: {src} not found", file=sys.stderr)
        return 1

    data = src.read_bytes()
    body = data if args.skip_header else data[HEADER_SIZE:]
    payload, markers = unframe(body)

    out_payload = src.with_suffix(src.suffix + ".decoded")
    out_markers = src.with_suffix(src.suffix + ".markers")
    out_payload.write_bytes(payload)
    out_markers.write_bytes(markers)

    print(f"source          {src} ({len(data):,} B, body {len(body):,} B)")
    print(f"payload         {out_payload} ({len(payload):,} B)")
    print(f"markers         {out_markers} ({len(markers):,} B, "
          f"{len(markers)/len(body)*100:.1f}% of body)")
    if args.strings:
        print("printable runs:")
        for off, s in printable_runs(payload, args.min_len):
            print(f"  {off:8d}  {s!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

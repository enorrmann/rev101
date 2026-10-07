#!/usr/bin/env python3
"""Security tests: a hostile firmware image must not escape the extract dir.

The QSPI entry-name field is a fixed 16 bytes taken straight from the image.
If an entry is named `../../evil` or `/etc/cron.d/x`, extraction must not write
outside the output directory.

Run:  python3 tests/test_safety.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import mc101fw as fw  # noqa: E402


def make_qspi_with_names(names: list[str], payload: bytes = b"PWNED") -> bytes:
    """Build a minimal QSPI image containing entries with the given names."""
    entries = []
    off = 0x1000
    for n in names:
        entries.append(fw.QspiEntry(name=n, offset=off, size=len(payload),
                                    crc=0, ext=0, data=payload))
        off += 0x1000
    img = fw.QspiImage(prefix=bytes(0x30), entry_base=0x30,
                       entry_count=len(entries), entries=entries)
    img.total_size = off
    return fw.build_qspi(img)


def main() -> int:
    failures = 0
    checks = 0

    # Names that reduce to a safe basename are ACCEPTED (that is correct and
    # desirable -- the original images contain names like "tone_pcmx_cmn.bi").
    sanitized = {
        "../../../../tmp/rev101_escape_marker": "rev101_escape_marker",
        "..\\..\\windows_style": "windows_style",
        "sub/../../escape": "escape",
        "/tmp/abs_name": "abs_name",
    }
    for name, expect in sanitized.items():
        checks += 1
        try:
            got = fw.safe_entry_name(name, 0)
        except fw.FirmwareError as ex:
            failures += 1
            print(f"FAIL  rejected a name that should sanitize: {name!r} ({ex})")
            continue
        if got != expect:
            failures += 1
            print(f"FAIL  {name!r} -> {got!r}, expected {expect!r}")
        elif "/" in got or "\\" in got or got.startswith("."):
            failures += 1
            print(f"FAIL  sanitized name still unsafe: {name!r} -> {got!r}")
        else:
            print(f"PASS  sanitized {name!r} -> {got!r}")

    # Names that cannot be made safe must be rejected outright.
    for name in (".", "..", "", "   ", "\x01\x02evil"):
        checks += 1
        try:
            bad = fw.safe_entry_name(name, 0)
        except fw.FirmwareError:
            print(f"PASS  rejected unsafe name {name!r}")
            continue
        failures += 1
        print(f"FAIL  accepted unsafe name {name!r} -> {bad!r}")

    # end-to-end: extraction must stay inside the output directory
    checks += 1
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        outdir = tmp / "out"
        outdir.mkdir()

        # a name that sanitizes to a safe basename must land inside outdir
        img = make_qspi_with_names(["../escaped.bin"])
        entries = fw.extract_qspi(img, outdir)
        landed = list(outdir.rglob("*"))
        escaped = (tmp / "escaped.bin").exists() or (tmp.parent / "escaped.bin").exists()
        if escaped or not any(p.name == "escaped.bin" for p in landed if p.is_file()):
            failures += 1
            print(f"FAIL  extraction escaped or misplaced: {landed}")
        else:
            print("PASS  traversal name sanitized into the output directory")

        # an absolute-looking path must also stay inside (<=16 bytes to fit the
        # on-image name field)
        checks += 1
        img2 = make_qspi_with_names(["/tmp/abs_escape"])
        fw.extract_qspi(img2, outdir)
        if Path("/tmp/abs_escape").exists():
            failures += 1
            print("FAIL  absolute name escaped to /tmp")
        else:
            print("PASS  absolute name did not escape")

    # resolve_within must reject a constructed escape
    checks += 1
    with tempfile.TemporaryDirectory() as td:
        base = Path(td) / "base"
        base.mkdir()
        for bad in ("../x", "../../x", "/etc/passwd"):
            try:
                fw.resolve_within(base, bad)
            except fw.FirmwareError:
                continue
            failures += 1
            print(f"FAIL  resolve_within allowed {bad!r}")
            break
        else:
            print("PASS  resolve_within rejects escapes")

    # decompression-bomb guard: must actually reject, not merely be defined.
    # tarfile will not emit a header whose size exceeds the supplied data, so
    # the header is written through the internal format writer instead.
    checks += 1
    import io as _io
    import tarfile as _tarfile

    buf = _io.BytesIO()
    tf = _tarfile.open(fileobj=buf, mode="w", format=_tarfile.USTAR_FORMAT)
    ti = _tarfile.TarInfo(name="bomb.bin")
    ti.size = fw.MAX_MEMBER_BYTES + 1
    tf.fileobj.write(ti.tobuf(format=_tarfile.USTAR_FORMAT))
    tf.fileobj.write(b"\x00" * 1024)
    tf.fileobj.flush()
    bomb = buf.getvalue()
    tf.close()

    try:
        fw.parse_tar(bomb)
    except fw.FirmwareError:
        print("PASS  oversized tar member rejected from the raw header")
    except Exception as ex:
        failures += 1
        print(f"FAIL  wrong error for oversized member: {type(ex).__name__}: {ex}")
    else:
        failures += 1
        print("FAIL  parse_tar accepted an oversized member (limit not enforced)")

    checks += 1
    if fw.MAX_CONTAINER_BYTES > 0 and fw.MAX_MEMBER_BYTES > 0:
        print(f"PASS  size limits set "
              f"(container {fw.MAX_CONTAINER_BYTES:,}, member {fw.MAX_MEMBER_BYTES:,})")
    else:
        failures += 1
        print("FAIL  container size limits not set")

    print()
    print(f"{checks - failures}/{checks} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

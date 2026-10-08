#!/usr/bin/env python3
"""Roland MC-101 (RPG69) firmware container tooling.

Handles the two nested container formats used by the `MC101_UPA_up.bin`
firmware updates:

  1. OUTER: a plain POSIX tar archive (ustar magic at 0x101) containing four
     raw flash images written to ./_tmp/.

  2. INNER: each of those images may itself carry a "QSPI " container:
         +0x20  "QSPI " + NUL padding          (magic)
         +0x24  u32 LE  0x20 (constant)
         +0x28  u32 LE  entry-base field    (u32 LE) = 0x20
         +0x2c  u32 LE  entry count         (u32 LE)
         entry (0x20 bytes, at entry_base + i*0x20):
             name[16] | offset u32 | size u32 | crc32 u32 | ext u32
     Entry payloads are 0x1000-aligned.

The `C1A`/`C1C` images additionally begin with a leading length prefix
(observed 0x003fff30 == filesize - 48, stored little-endian) followed by 48 NUL
bytes.

This module is deliberately dependency-free (stdlib only).
"""

from __future__ import annotations

import io
import struct
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants derived from the firmware analysis
# ---------------------------------------------------------------------------

TAR_MEMBERS = (
    "RPG69_C0A_up.bin",
    "RPG69_C0C_up.bin",
    "RPG69_C1A_up.bin",
    "RPG69_C1C_up.bin",
)

QSPI_MAGIC = b"QSPI "  # 5 bytes, followed by 3 NUL pad at +0x20
# Layout at +0x20 (verified against C1C and C0C in all three versions):
#   +0x20  "QSPI " + NUL padding         magic
#   +0x28  entry table offset (u32 LE)   value 0x20 observed
#   +0x2c  entry count (u32 LE)
#   +0x30  first entry header (0x20 B each)
#
# NOTE: the first entry always begins at 0x30 in every image we have; the
# 0x28 field (observed 0x20) is carried through unchanged by build_qspi and is
# not used to locate the table.  Using 0x28+0x20 as the absolute start is what
# produced the earlier "implausible entry base 0x20" failure; we derive the
# start explicitly instead.
QSPI_ENTRY_SIZE = 0x20
QSPI_ENTRY_BASE_FIELD = 0x28
QSPI_ENTRY_COUNT_OFF = 0x2C
QSPI_ENTRIES_START = 0x30

# C0A (App1_Main) header layout, plaintext, 0x60 bytes.
#
# Verified byte-for-byte against v1.80/1.81/1.82.  Field boundaries were
# established by aligning the three versions against each other and checking
# the size field against the actual member length.
#
#   0x00  16 B   "App1_Main\0..."     name
#   0x10  16 B   "2023/05/17 22:54"   date, NO NUL terminator (runs to 0x1f)
#   0x20   8 B   "0.010001"           version string
#   0x28   4 B   0x00000060           load offset (= 0x60, big-endian u32)
#   0x2c   4 B   0x00000000           zero
#   0x30   4 B   0x000c0040           load address (big-endian u32)
#   0x34  12 B   0xffffffff x3        erased region
#   0x40   4 B   0x000c0060           load offset/addr mirror
#   0x44   4 B   0x003565b0           payload size, big-endian (see SIZE_SEMANTICS)
#   0x48   4 B   0x00000060
#   0x4c   4 B   0x00000000
#   0x50   4 B   0x513fc2d9           digest (big-endian u32)
#   0x54   4 B   0xb6020001           flags / format id
#   0x58   4 B   0x00000000
#   0x5c   4 B   0xffffffff
#
# SIZE_SEMANTICS: for v1.82, field == 0x3565b0 while filesize == 0x356650.
# The difference is 0xa0, and 0x3565b0 + 0x50 == filesize - 0x50.  The field
# therefore describes the payload span excluding the final 0xa0 bytes of tail,
# not simply (filesize - header).  We expose the raw value rather than
# asserting an equality we cannot justify.
C0A_HEADER_SIZE = 0x60
C0A_NAME_OFF = 0x00
C0A_NAME_LEN = 0x10
C0A_DATE_OFF = 0x10
C0A_DATE_LEN = 0x10  # 16 bytes: "YYYY/MM/DD HH:MM", no terminator
C0A_VER_OFF = 0x20
C0A_VER_LEN = 0x08  # "0.010001"
C0A_LOAD_OFF = 0x2C
C0A_LOAD_ADDR_OFF = 0x30
C0A_MIRROR_OFF = 0x40
C0A_SIZE_OFF = 0x44
C0A_DIGEST_OFF = 0x50
C0A_FLAGS_OFF = 0x54


class FirmwareError(Exception):
    """Raised for malformed or unsupported firmware structures."""


# ---------------------------------------------------------------------------
# Outer container: tar
# ---------------------------------------------------------------------------


@dataclass
class TarMember:
    name: str
    size: int
    offset: int  # offset of the member's data within the container
    data: bytes = field(repr=False, default=b"")
    mode: int = 0o777
    uid: int = 1000
    gid: int = 1000
    mtime: int = 0
    uname: str = ""
    gname: str = ""


# Guard against decompression bombs: a small crafted archive must not be able
# to expand into unbounded memory.  Real firmware containers are ~20 MB.
MAX_CONTAINER_BYTES = 256 * 1024 * 1024  # 256 MiB
MAX_MEMBER_BYTES = 256 * 1024 * 1024


def parse_tar(data: bytes) -> list[TarMember]:
    """Parse the outer tar archive, preserving raw member data.

    Size limits are enforced from the raw 512-byte headers BEFORE handing the
    buffer to `tarfile`, so a header declaring an enormous member is rejected
    without tarfile attempting to read it.
    """
    _check_tar_header_sizes(data)

    members: list[TarMember] = []
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            if m.size > MAX_MEMBER_BYTES:
                raise FirmwareError(
                    f"member {m.name!r} declares {m.size:,} bytes, "
                    f"exceeding the {MAX_MEMBER_BYTES:,} safety limit"
                )
            total += m.size
            if total > MAX_CONTAINER_BYTES:
                raise FirmwareError(
                    f"tar expands beyond the {MAX_CONTAINER_BYTES:,} byte safety limit"
                )
            fh = tf.extractfile(m)
            if fh is None:
                continue
            members.append(
                TarMember(
                    name=m.name,
                    size=m.size,
                    offset=m.offset_data,
                    data=fh.read(),
                    mode=m.mode,
                    uid=m.uid,
                    gid=m.gid,
                    mtime=m.mtime,
                    uname=m.uname,
                    gname=m.gname,
                )
            )
    if not members:
        raise FirmwareError("no regular files found in tar container")
    return members


def _check_tar_header_sizes(data: bytes) -> None:
    """Walk the raw 512-byte tar headers and reject oversized members early.

    Runs before tarfile sees the buffer, so a bomb is refused on the strength
    of its declared size rather than after tarfile starts reading it.
    """
    off = 0
    n = len(data)
    while off + 512 <= n:
        block = data[off : off + 512]
        if block == b"\x00" * 512:
            return  # end-of-archive marker

        size_field = block[124:136]
        if size_field == b"\x00" * 12:
            return  # end of headers
        try:
            # GNU tar uses base-256 for values that do not fit octal.
            first = size_field[0]
            if first == 0xFF:  # 0o377: negative two's-complement
                value = int.from_bytes(size_field[1:], "big", signed=False)
                value -= 1 << ((len(size_field) - 1) * 8)
            elif first & 0x80:  # 0o200: positive base-256
                value = int.from_bytes(size_field[1:], "big", signed=False)
            else:
                value = int(size_field.split(b"\x00")[0].strip() or b"0", 8)
        except ValueError:
            # malformed size: skip this header's data block conservatively but
            # keep scanning rather than abandoning the rest of the archive
            off += 512
            continue

        if value < 0:
            off += 512
            continue

        if value > MAX_MEMBER_BYTES:
            name = block[0:100].split(b"\x00")[0].decode("latin-1", "replace")
            raise FirmwareError(
                f"tar member {name!r} declares {value:,} bytes, "
                f"exceeding the {MAX_MEMBER_BYTES:,} safety limit"
            )
        off += 512 + ((value + 511) // 512) * 512


def build_tar(members: list[TarMember]) -> bytes:
    """Rebuild a tar container matching Roland's format byte-for-byte.

    Roland's tar is produced by GNU tar: numeric uid/gid (1000), mode 0777,
    EMPTY uname/gname, and the GNU "ustar  \\0" magic variant.  The mtime of
    each member must be carried through from the original, otherwise the
    rebuild differs in every header block.

    Python's tarfile cannot emit the exact "ustar  \\0" spelling or empty
    uname/gname via normal fields, so the header is assembled manually.
    """
    blocks = bytearray()
    for m in members:
        hdr = bytearray(512)

        name = m.name.encode("latin-1")
        if len(name) > 100:
            raise FirmwareError(f"member name too long for ustar: {m.name!r}")
        hdr[0:len(name)] = name

        # octal numeric fields, NUL-terminated: mode, uid, gid, size, mtime
        def oct_field(off: int, width: int, value: int) -> None:
            s = ("%0*o" % (width - 1, value)).encode("ascii")
            if len(s) > width - 1:
                raise FirmwareError(f"value {value} does not fit in {width} bytes")
            hdr[off:off + width - 1] = s
            hdr[off + width - 1] = 0

        oct_field(100, 8, m.mode)
        oct_field(108, 8, m.uid)
        oct_field(116, 8, m.gid)
        oct_field(124, 12, len(m.data))
        oct_field(136, 12, m.mtime)

        # checksum: spaces during computation, then "%06o\0 "
        for i in range(148, 156):
            hdr[i] = 0x20
        hdr[156] = 0x30  # typeflag '0' (regular file)
        # linkname (157..257) stays NUL
        # magic "ustar  \0" (GNU) then version-compatible trailer
        hdr[257:265] = b"ustar  \x00"
        # uname/gname intentionally EMPTY (Roland writes none)
        # devmajor/devminor left NUL, prefix left NUL
        cksum = sum(hdr)
        hdr[148:156] = ("%06o" % cksum).encode("ascii") + b"\x00 "

        blocks += hdr
        blocks += m.data
        pad = (-len(m.data)) % 512
        if pad:
            blocks += b"\x00" * pad

    # tar end-of-archive: two zero blocks, then pad to the blocking factor
    blocks += b"\x00" * 1024
    pad = (-len(blocks)) % 10240
    if pad:
        blocks += b"\x00" * pad
    return bytes(blocks)


# ---------------------------------------------------------------------------
# Inner container: QSPI
# ---------------------------------------------------------------------------


@dataclass
class QspiEntry:
    name: str
    offset: int
    size: int
    crc: int
    ext: int
    data: bytes = field(repr=False, default=b"")


@dataclass
class QspiImage:
    prefix: bytes  # leading length prefix + padding, if any
    entry_base: int
    entry_count: int
    entries: list[QspiEntry]


def is_qspi(data: bytes) -> bool:
    """A QSPI container declares its magic at +0x20."""
    return len(data) > 0x40 and data[0x20 : 0x20 + len(QSPI_MAGIC)] == QSPI_MAGIC


def parse_qspi(data: bytes) -> QspiImage:
    """Parse a QSPI container, extracting all entries."""
    if not is_qspi(data):
        raise FirmwareError("not a QSPI container (magic 'QSPI ' not at +0x20)")

    entry_base_field = struct.unpack_from("<I", data, QSPI_ENTRY_BASE_FIELD)[0]
    entry_count = struct.unpack_from("<I", data, QSPI_ENTRY_COUNT_OFF)[0]

    if entry_count == 0 or entry_count > 4096:
        raise FirmwareError(f"implausible entry count {entry_count}")

    start = QSPI_ENTRIES_START
    if start + entry_count * QSPI_ENTRY_SIZE > len(data):
        raise FirmwareError(
            f"entry table ({entry_count} x {QSPI_ENTRY_SIZE:#x}) runs past image end"
        )

    entries: list[QspiEntry] = []
    for i in range(entry_count):
        off = start + i * QSPI_ENTRY_SIZE
        raw = data[off : off + QSPI_ENTRY_SIZE]
        name = raw[0:16].split(b"\x00", 1)[0].decode("latin-1")
        e_off, e_size, e_crc, e_ext = struct.unpack("<IIII", raw[0x10:0x20])
        if e_off + e_size > len(data):
            raise FirmwareError(f"entry {i} ({name}) exceeds image bounds")
        entries.append(
            QspiEntry(
                name=name,
                offset=e_off,
                size=e_size,
                crc=e_crc,
                ext=e_ext,
                data=data[e_off : e_off + e_size],
            )
        )

    prefix = data[:start]
    img = QspiImage(
        prefix=prefix, entry_base=start, entry_count=entry_count, entries=entries
    )
    img.entry_base_field = entry_base_field  # type: ignore[attr-defined]
    img.total_size = len(data)  # type: ignore[attr-defined]
    img.original = data  # type: ignore[attr-defined]
    return img


def build_qspi(img: QspiImage) -> bytes:
    """Rebuild a QSPI container from its entry list.

    Layout is reproduced faithfully: magic + entry base + count at +0x20,
    then entry headers, then each payload placed at its recorded offset.

    IMPORTANT: each entry's declared `size` field under-reports the real
    payload extent by a short tail (1..~30 bytes of genuine data observed at
    every entry boundary, e.g. 0x1050 after wromInfo_KY022.b).  Rebuilding
    purely from `size` therefore zeroes that tail.  When the original image
    bytes are available we use them as the base so those tails are preserved
    exactly; otherwise we fall back to a zero-filled build.
    """
    original = getattr(img, "original", None)

    recorded = getattr(img, "total_size", 0)
    total = max(
        recorded,
        max((e.offset + e.size for e in img.entries), default=img.entry_base),
    )
    if not recorded:
        total = (total + 0xFFF) & ~0xFFF

    if original is not None and len(original) == total:
        buf = bytearray(original)
    else:
        buf = bytearray(total)
        # preserve the leading prefix (length word + padding) exactly
        buf[0 : len(img.prefix)] = img.prefix

    buf[0x20 : 0x20 + len(QSPI_MAGIC)] = QSPI_MAGIC
    struct.pack_into(
        "<I", buf, QSPI_ENTRY_BASE_FIELD, getattr(img, "entry_base_field", 0x20)
    )
    struct.pack_into("<I", buf, QSPI_ENTRY_COUNT_OFF, len(img.entries))

    for i, e in enumerate(img.entries):
        off = img.entry_base + i * QSPI_ENTRY_SIZE
        name = e.name.encode("latin-1")
        if len(name) > 16:
            raise FirmwareError(f"entry name too long for 16-byte field: {e.name!r}")
        # Names are stored in a fixed 16-byte field WITHOUT a guaranteed NUL:
        # an exactly-16-char name fills the field completely (e.g.
        # "tone_pcmx_cmn.bi").  Only pad when shorter.
        name = name.ljust(16, b"\x00")
        buf[off : off + 16] = name
        struct.pack_into("<IIII", buf, off + 0x10, e.offset, len(e.data), e.crc, e.ext)
        end = e.offset + len(e.data)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[e.offset : end] = e.data

    return bytes(buf)


def safe_entry_name(name: str, index: int = -1) -> str:
    """Sanitize a firmware-controlled QSPI entry name for use as a filename.

    Entry names come from the parsed image and are attacker-controlled if the
    image is untrusted.  A name like `../../x` or `/etc/passwd` must not be
    allowed to escape the extraction directory, so we reduce it to a basename
    and reject anything that still looks like a path or is empty.

    Raises FirmwareError if the name cannot be made safe.
    """
    raw = name.strip().rstrip("\x00")
    # strip any directory components (both separators, since images are
    # produced on arbitrary hosts)
    base = raw.replace("\\", "/").split("/")[-1].strip()

    if not base or base in (".", ".."):
        raise FirmwareError(f"entry {index}: unsafe empty/relative name {name!r}")
    if base.startswith("~"):
        raise FirmwareError(f"entry {index}: unsafe name {name!r}")
    # reject control characters and anything that could confuse a shell
    if any(ord(c) < 0x20 or c in '\x7f' for c in base):
        raise FirmwareError(f"entry {index}: control characters in name {name!r}")
    return base


def resolve_within(base_dir: Path, name: str) -> Path:
    """Join `name` under `base_dir`, guaranteeing the result stays inside it.

    Defence in depth alongside `safe_entry_name`: even if a name somehow still
    contains path components, the resolved target must remain under base_dir.
    """
    target = (base_dir / name).resolve()
    root = base_dir.resolve()
    if target != root and root not in target.parents:
        raise FirmwareError(f"refusing to write outside {root}: {name!r}")
    return target


def extract_qspi(data: bytes, outdir: Path) -> list[QspiEntry]:
    """Extract every QSPI entry to `outdir`; returns the entry list."""
    img = parse_qspi(data)
    outdir.mkdir(parents=True, exist_ok=True)
    for i, e in enumerate(img.entries):
        target = resolve_within(outdir, safe_entry_name(e.name, i))
        target.write_bytes(e.data)
    return img.entries


# ---------------------------------------------------------------------------
# C0A / App1_Main header
# ---------------------------------------------------------------------------


@dataclass
class App1Header:
    name: str
    date: str
    version: str
    load_off: int
    load_addr: int
    declared_size: int
    digest: int
    flags: int

    def size_consistent(self, total_len: int) -> bool:
        """The size field is less than (filesize - header) by a fixed 0xa0 tail.

        Observed for v1.82: field 0x3565b0, filesize 0x356650, delta 0xa0.
        We verify the delta is non-negative and within a sane bound rather
        than pretending to a byte-exact rule we have not proven.
        """
        return 0 <= (total_len - C0A_HEADER_SIZE) - self.declared_size < 0x1000


def parse_app1_header(data: bytes) -> App1Header:
    """Parse the plaintext 0x60-byte header of an App1_Main image (C0A)."""
    if len(data) < C0A_HEADER_SIZE:
        raise FirmwareError("image smaller than App1 header")
    name = data[C0A_NAME_OFF : C0A_NAME_OFF + C0A_NAME_LEN].split(b"\x00", 1)[0]
    date = data[C0A_DATE_OFF : C0A_DATE_OFF + C0A_DATE_LEN]
    date = date.split(b"\x00", 1)[0]  # no terminator normally, but be safe
    ver = data[C0A_VER_OFF : C0A_VER_OFF + C0A_VER_LEN].split(b"\x00", 1)[0]
    load_off = struct.unpack_from("<I", data, C0A_LOAD_OFF)[0]
    load_addr = struct.unpack_from("<I", data, C0A_LOAD_ADDR_OFF)[0]
    declared_size = struct.unpack_from("<I", data, C0A_SIZE_OFF)[0]
    digest = struct.unpack_from("<I", data, C0A_DIGEST_OFF)[0]
    flags = struct.unpack_from("<I", data, C0A_FLAGS_OFF)[0]
    return App1Header(
        name=name.decode("latin-1"),
        date=date.decode("latin-1"),
        version=ver.decode("latin-1"),
        load_off=load_off,
        load_addr=load_addr,
        declared_size=declared_size,
        digest=digest,
        flags=flags,
    )


# ---------------------------------------------------------------------------
# Convenience: full container
# ---------------------------------------------------------------------------


def load_container(path: str | Path) -> bytes:
    """Load a firmware container from either a .zip release or a raw .bin.

    Roland ships the update as a ZIP containing MC101_UPA_up.bin.  Accept
    both so tooling can run against the original download.
    """
    p = Path(path)
    raw = p.read_bytes()
    if raw[:2] == b"PK":
        import zipfile

        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            if not infos:
                raise FirmwareError(f"{p.name}: zip contains no files")
            # Bound the expansion BEFORE reading, so a crafted zip cannot
            # exhaust memory ahead of the tar-level checks in parse_tar.
            for i in infos:
                if i.file_size > MAX_MEMBER_BYTES:
                    raise FirmwareError(
                        f"{i.filename!r} declares {i.file_size:,} bytes, "
                        f"exceeding the {MAX_MEMBER_BYTES:,} safety limit"
                    )
            total = sum(i.file_size for i in infos)
            if total > MAX_CONTAINER_BYTES:
                raise FirmwareError(
                    f"zip expands beyond the {MAX_CONTAINER_BYTES:,} byte safety limit"
                )
            # prefer the UPA payload if present
            target = next(
                (i for i in infos if "UPA" in i.filename.upper()), infos[0]
            )
            # read with a hard ceiling and reject truncation rather than
            # silently returning a short buffer
            with zf.open(target) as fh:
                blob = fh.read(MAX_MEMBER_BYTES + 1)
            if len(blob) > MAX_MEMBER_BYTES:
                raise FirmwareError(
                    f"{target.filename!r} exceeds the "
                    f"{MAX_MEMBER_BYTES:,} byte safety limit"
                )
            return blob
    return raw


def open_firmware(path: str | Path) -> list[TarMember]:
    """Read a MC101_UPA_up.bin style archive and return its raw members."""
    return parse_tar(load_container(path))


def describe(path: str | Path) -> str:
    """Human-readable structure dump for a firmware container."""
    lines: list[str] = []
    members = open_firmware(path)
    lines.append(f"{Path(path).name}: tar container, {len(members)} members")
    for m in members:
        base = m.name.split("/")[-1]
        lines.append(f"  {base:24s} size={len(m.data):>10,}")
        if is_qspi(m.data):
            img = parse_qspi(m.data)
            lines.append(
                f"      QSPI container: {img.entry_count} entries, "
                f"entry_base={img.entry_base:#x}, prefix={len(img.prefix)}B"
            )
            for e in img.entries:
                lines.append(
                    f"        {e.name.strip():24s} off={e.offset:#09x} "
                    f"size={e.size:>10,} crc={e.crc:#010x}"
                )
        elif m.data[:9].rstrip(b"\x00") == b"App1_Main":
            h = parse_app1_header(m.data)
            lines.append(
                f"      App1 image: name={h.name!r} date={h.date!r} "
                f"ver={h.version!r}"
            )
            lines.append(
                f"        load_off={h.load_off:#x} load_addr={h.load_addr:#x} "
                f"size={h.declared_size:>10,} "
                f"size_consistent={h.size_consistent(len(m.data))} "
                f"digest={h.digest:#010x} flags={h.flags:#010x}"
            )
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    for p in sys.argv[1:]:
        print(describe(p))
        print()

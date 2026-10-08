# Building a modified MC-101 firmware image

This describes the **container mechanics**, which are solved and verified.
What you can currently change, and what still blocks a fully custom build, is
stated plainly at the end — read [Current limits](#current-limits) before
planning work.

> **Hardware warning.** Writing a bad image to the device can brick it. Nothing
> in this repository writes to hardware. Build and inspect images here; you own
> the decision to flash anything.

## Quick start

```sh
make test                 # prove the tooling round-trips byte-exactly
make extract-all          # unpack v1.80/1.81/1.82 into firmware/raw/
```

## Container structure recap

```
MC101_UPA_up.bin                plain tar (ustar), 4 members
└── RPG69_C0A_up.bin            3,499,600 B   main CPU app   (0x60 header + body)
└── RPG69_C0C_up.bin            8,388,576 B   main CPU sample bank  ("QSPI " container)
└── RPG69_C1A_up.bin            4,194,144 B   secondary MCU         ("QSPI " container)
└── RPG69_C1C_up.bin            4,194,144 B   secondary MCU ROM data("QSPI " container)
```

QSPI layout: magic at `+0x20`, entry table at `0x30`, entries of
`name[16] | offset | size | crc32 | ext`, payloads at 0x1000-aligned offsets.

## Modifying a QSPI member

```python
import sys; sys.path.insert(0, "tools")
import mc101fw as fw

raw = fw.load_container("mc101_sys_v182.zip")
members = fw.parse_tar(raw)

out = []
for m in members:
    data = m.data
    if fw.is_qspi(data):
        img = fw.parse_qspi(data)
        for e in img.entries:
            if e.name.strip() == "sdram1.bin":
                e.data = open("my_sdram1.bin", "rb").read()   # your replacement
        data = fw.build_qspi(img)
    out.append(fw.TarMember(name=m.name, size=len(data), offset=0, data=data,
                            mode=m.mode, uid=m.uid, gid=m.gid,
                            mtime=m.mtime, uname=m.uname, gname=m.gname))

open("MC101_UPA_up.bin", "wb").write(fw.build_tar(out))
```

Then copy that file into a zip named `mc101_sys_v182.zip` to match Roland's
layout, if the updater expects the original filename.

### Rules the rebuild must respect

1. **Carry metadata through.** `mode`, `uid`, `gid`, `mtime`, `uname`, `gname`
   must be copied from the parsed member. Roland's tar uses mode 0777,
   uid/gid 1000 (numeric, not names), and GNU's `ustar  \0` magic. Dropping the
   mtime alone breaks byte-exactness in every header block.
2. **Keep 0x1000 alignment.** Payload offsets in the entry table are 0x1000
   aligned. `build_qspi` places payloads at their recorded `offset`; if you
   change a payload's size, keep the entry's `offset` consistent with the next
   entry.
3. **Entry `size` is a lower bound.** The declared size under-reports the real
   payload by a short tail (1..~30 bytes) at each boundary. `build_qspi` uses
   the original image bytes as its base so those tails survive. If you build an
   image from scratch rather than by modifying a parsed one, you must account
   for those tails yourself.
4. **Names are 16 raw bytes.** No guaranteed NUL. Keep ≤16 characters.

## Verifying your build

The strongest check is the round-trip:

```sh
make test          # or:
python3 tests/test_full_rebuild.py
```

It asserts `extract -> rebuild == original` byte-for-byte for all three
releases. **If that passes on pristine input, then any byte difference in your
modified image is exactly your intended change** — nothing else can drift.

Additional checks worth running on a modified image:

* `python3 tools/mc101fw.py <your_image>` — re-parse your own output and confirm
  the entry table, sizes and names are what you intended.
* Confirm the entry count and offsets are unchanged unless you meant to change
  them.
* Diff your image against the original and confirm the diff regions match your
  intent:
  ```sh
  cmp -l original.bin modified.bin | wc -l
  ```

## Current limits

Honest status of what is and is not yet possible.

**Works today:**

* Extract/repack every container byte-exactly (verified, all three versions).
  The device's own QSPI parser confirms the layout: magic, 0x20-byte entries,
  16-byte case-insensitive names with non-printables folded to `_`
  ([SECONDARY_MCU.md](SECONDARY_MCU.md), [FINDINGS.md](FINDINGS.md) §8.1.1).
* Replace any QSPI entry payload, including `sdram1.bin` / `idm1.bin`, which
  are **plaintext ARM Cortex-M code** and fully readable.
* Edit the plaintext `C1C` entries and `C0C` metadata entries.

**Not yet possible:**

* **Rebuilding `C0A` with modified application code.** The C0A body contains a
  1.1 MB incompressible window (`0x0c0000`–`0x1d0000`, exactly 1,114,112 B)
  whose protection mechanism is undetermined. You can currently only copy it
  through unmodified.
* **Editing `init.lzs` field-by-field.** `init.lzs` is *not* compressed — it is
  a 4-bit-framed stream (drop every byte whose low nibble is `f` to recover the
  payload; `tools/unlzs.py`), so there is no decompressor to find and none is
  needed. The header tags and drum-kit fragment names are readable today; what
  is still unresolved is the `PRJ5` field-level record schema, so the runtime
  cannot yet be edited field-by-field. See [FINDINGS.md](FINDINGS.md) §6.
* **Knowing whether the bootloader accepts an unmodified-but-repacked image.**
  The container has no signature table, so the format presents no obstacle —
  but the verification behaviour of a first-stage bootloader we have not
  located is unknown.

**Unverified, not just impossible:**

* The entry-table `crc32` is **not** a checksum of the payload — no candidate
  reproduces it for any entry ([FINDINGS.md](FINDINGS.md) §8.1.3). The
  algorithm is confirmed to be CRC-32, but the byte range it covers is not, so
  the tooling cannot independently confirm that a *modified* image is
  internally consistent. The repack carries the field through unchanged, which
  is why the round-trip stays byte-exact.

**Therefore the realistic custom-firmware target right now is the secondary
MCU** (`C1A` → `sdram1.bin` / `idm1.bin`), which involves no cryptography at
all. Two constraints on a replacement, both from the decompiled loader:

* the payload must be **raw, uncompressed bytes** — the QSPI reader never
  transforms what it reads; and
* the `0x1c`-byte descriptor the loader fills per entry ends in a **base
  pointer computed as `stored + file_base`**, so the replacement has to satisfy
  that expectation or boot will follow a bad pointer.

See [FINDINGS.md](FINDINGS.md) §8 for the recommended order of work.

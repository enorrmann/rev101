# USAGES — what you can actually do in this state of the project

A practical, command-level guide to the **currently working** capabilities of
this workspace, with worked examples that build several *test* custom
firmwares end to end.

Everything below is offline work on files. **No step here writes to hardware**;
every example ends with an image you can inspect, not one that is flashed.

What is possible today, in one table:

| capability | state |
|---|---|
| unpack / repack every container **byte-exactly** (v1.80/1.81/1.82) | **works** |
| read every container field the device itself uses | **works** |
| replace any QSPI entry payload (`idm1.bin`, `sdram1.bin`, `C0C`/`C1C` data entries) | **works** |
| add / resize / synthesise QSPI entries | **works** (untested on hardware) |
| edit text inside a plaintext entry in place (`qspi_ver_def.h`, `spf_muse_*`, …) | **works** |
| rebuild `C0A` (main-CPU app) with modified code | **blocked** — 1.1 MB incompressible window, see [FINDINGS.md](FINDINGS.md) §4 |
| decompress `init.lzs` | **partial** — PRJ5 project; framing `[data][0xXf]` confirmed & names readable (`tools/unlzs.py`), field schema unresolved; see [FINDINGS.md](FINDINGS.md) §6 |
| know whether the bootloader accepts a repacked image | **unknown** — first stage not in these images |
| recompute the entry-table `crc32` for a modified entry | **unknown** — algorithm is CRC-32, covered range is not ([§8.1.3](FINDINGS.md)) |

Read [PATCHING.md](PATCHING.md) for the container mechanics and
[FINDINGS.md](FINDINGS.md) for the evidence behind the blocked rows.

---

## 0. Prerequisites

* `python3` (3.8+) — the tooling is **stdlib only**, no pip installs.
* Anything that can read a tar (`tar tvf`) for spot checks.
* Optional: a Ghidra install, only for the decompilation workflow (§9).
  The scripts default to `/home/emilio/ghidras/ghidra_11.3.2_PUBLIC`; override
  with `GHIDRA=/path/to/ghidra`.
* The three release zips in the repository root: `mc101_sys_v180.zip`,
  `mc101_sys_v181.zip`, `mc101_sys_v182.zip`.

> **Hardware warning.** Flashing a bad image can brick the device. Nothing in
> this repository touches hardware; it writes image files and reports diffs.

## 1. Quick start

```sh
make help          # list targets
make test          # full verification suite
make inspect       # print container structure for all three versions
make extract-all   # unpack everything into firmware/raw/
make candidate     # build a demo modified image into build/
```

`.zip` files, `firmware/raw/`, `firmware/decoded/` and `build/` are gitignored,
so all generated output stays out of the tree.

## 2. First, prove the tooling (do this before trusting any diff)

```sh
$ make test
18/18 checks passed      tests/test_roundtrip.py
9/9  checks passed       tests/test_full_rebuild.py
9/9  checks passed       tests/test_patch.py
14/14 checks passed      tests/test_safety.py
2/2  checks passed       tests/test_unlzs.py
4/4  checks passed       tests/test_rb_record.py
```

`test_full_rebuild.py` is the acceptance test: `extract -> repack` reproduces
the original 20,285,440-byte container **byte-for-byte for all three releases**.
That is what makes the recipes below trustworthy — if a pristine rebuild has
zero drift, then every byte that differs in your modified image is a byte *you*
changed.

## 3. Look before you touch

```sh
make inspect                                   # all three versions
python3 tools/mc101fw.py mc101_sys_v182.zip    # or one file
python3 tools/mc101fw.py build/MC101_UPA_up.bin  # …or your own output
```

Real output for v1.82 (abridged):

```
mc101_sys_v182.zip: tar container, 4 members
  RPG69_C0A_up.bin         size= 3,499,600
      App1 image: name='App1_Main' date='2023/05/17 22:54' ver='0.010001'
        load_off=0x0 load_addr=0xc0040 size= 3,499,440 size_consistent=True ...
  RPG69_C0C_up.bin         size= 8,388,576
      QSPI container: 12 entries, entry_base=0x30, prefix=48B
        tone_pcmx_cmn.bi         off=0x0001000 size= 1,198,624 crc=0x00005dfe
        ...
        init.lzs                 off=0x060e000 size=   969,045 crc=0x00006be9
  RPG69_C1A_up.bin         size= 4,194,144
      QSPI container: 2 entries, entry_base=0x30, prefix=48B
        idm1.bin                 off=0x0001000 size=   241,796 crc=0x0000348c
        sdram1.bin               off=0x003d000 size= 3,709,724 crc=0x00001dbd
  RPG69_C1C_up.bin         size= 4,194,144
      QSPI container: 16 entries, entry_base=0x30, prefix=48B
        wromInfo_KY022.b         off=0x0001000 size=        64 crc=0x00000203
        ...
        qspi_ver_def.h           off=0x0147000 size=       123 crc=0x00005235
```

Three facts worth knowing before you patch:

* Payload offsets are **0x1000-aligned**, and each `size` is a **lower bound** —
  1..~30 bytes of genuine data follow every entry. `build_qspi` keeps the
  original image bytes as its base precisely so those tails survive.
* The `crc32` column is carried through **unchanged** by a repack. It is not a
  checksum of the payload, so it will look "stale" in a modified image and
  cannot be used to validate one.
* `idm1.bin` and `sdram1.bin` are **byte-identical across v1.80, v1.81 and
  v1.82** (sha256 `80f062ac…` and `e532f514…` respectively), so "swap the
  secondary MCU from another version" is not a change at all — edit the bytes
  instead (FW-2 below).

## 4. Unpack everything

```sh
make extract-all      # = python3 tools/extract.py --all --repack-check
```

Produces, per version (only v182 shown):

```
firmware/raw/v182/
  RPG69_C0A_up.bin   RPG69_C0C_up.bin   RPG69_C1A_up.bin   RPG69_C1C_up.bin
  RPG69_C0C_up_entries/  init.lzs  tone_pcmx_cmn.bi  tone_pcmEx_* …
  RPG69_C1A_up_entries/  idm1.bin  sdram1.bin
  RPG69_C1C_up_entries/  wromInfo_KY022.b  spf_muse_*  wpf_muse_*  qspi_ver_def.h …
```

`--repack-check` prints `REPACK CHECK: byte-identical  OK` for each version, so
one command both extracts and re-proves the round-trip.

### 4.1 Read `init.lzs` (the 4-bit-framed init data)

`init.lzs` is not compressed: it is a stream of plain 8-bit data bytes
interleaved with marker bytes whose low nibble is `f` (`0x0f`…`0xff`). Drop the
markers to read the payload:

```sh
make extract-all
python3 tools/unlzs.py firmware/raw/v182/RPG69_C0C_up_entries/init.lzs --strings
```

Writes:

```
…/init.lzs.decoded      498,599 B  the 8-bit payload (markers removed)
…/init.lzs.markers      470,382 B  the 4-bit marker values (one per marker)
…/init.lzs.strings.txt             printable runs (when --strings is used)
```

The decoded payload contains a **handful** of real Roland strings — byte-verified
against the raw image: the header tags `PRJ5`/`aMC7`/`STP`, `INIT`/`InitT`,
and the `TR-909`/`707`/`Cowbel` drum-kit fragment names (`TR-909 Kick 1`,
`Rimsht`, `Clap 2`, `MidG2M0`, `707 Tamb`). Most other short "printable"
runs (`1CUgy`, `0BTfx`, `2DVhz`, `4FXA…`, …) are **not** names or tags: they
are coincidences between the marker alphabet and ASCII in the binary parameter
tables. See [FINDINGS.md](FINDINGS.md) §6 for the byte-verified table and the
still-open questions (12-bit fields `(marker>>4)<<8 | byte`, record schema).

---

## 5. The three ways to modify an image

All three end at the same place: a `MC101_UPA_up.bin` whose tar and QSPI
structures are valid and whose diff against the base is exactly your change.

### 5.1 Same-size edit in place (safest)

Change some bytes inside an existing plaintext entry **without changing its
size**. Nothing moves: no offsets, no table, no tails. This is what
`make candidate` does, and it is the right shape for a first hardware test.

```sh
make candidate
```

```
base: mc101_sys_v182.zip (20,285,440 B)
edit: RPG69_C1C_up.bin:qspi_ver_def.h  0.039 -> 9.999
  entry 123 B, 3 bytes edited

wrote build/MC101_UPA_up.bin
  size   : 20,285,440 B (base 20,285,440 B)
  sha256 : daa7ae1037e666e3c1b31f02f29f71269e952ea613a6be05953886a47ba5f9dd
  diff   : 3 bytes, first at 0x109e054
```

### 5.2 Replace a whole QSPI entry payload — `tools/patch.py`

```sh
python3 tools/patch.py \
  --base mc101_sys_v182.zip \
  --out  build/MC101_UPA_up.bin \
  --replace MEMBER:ENTRY:FILE     # repeatable
```

* `MEMBER` is matched as a **substring** of the tar member name, so `C1A`,
  `C1C`, `RPG69_C1A_up.bin` all work.
* `ENTRY` must match the 16-byte entry name exactly (`.strip()`ed).
* Repeat `--replace` to patch several entries in one build. Every replacement
  must apply, or the tool exits non-zero without writing anything.

Example (one entry, six changed bytes):

```sh
$ python3 tools/patch.py --base mc101_sys_v182.zip --out build/MC101_UPA_idm1.bin \
      --replace RPG69_C1A_up.bin:idm1.bin:/tmp/rev101/usages/idm1_test.bin
base: mc101_sys_v182.zip
  will replace RPG69_C1A_up.bin:idm1.bin <- /tmp/rev101/usages/idm1_test.bin

  replace RPG69_C1A_up.bin:idm1.bin 241,796 B -> 241,796 B  (sha 80f062ac8d050fbf -> 0c98743865d14ae4)

wrote build/MC101_UPA_idm1.bin  (20,285,440 B, sha256 b66274d8f2c07d88fe0928a405fe1694)
diff vs base: 6 bytes differ, first at 0xb60450
```

A bad entry name fails loudly and changes nothing:

```sh
$ python3 tools/patch.py --base mc101_sys_v182.zip --out /tmp/nope.bin \
      --replace RPG69_C1A_up.bin:does_not_exist.bin:x.bin
error: entry 'does_not_exist.bin' not found in RPG69_C1A_up.bin
exit=1
```

> There is no `--replace-in-place` flag: an in-place same-size edit is just a
> `--replace` whose file has the original length, and the container length is
> unchanged automatically.

### 5.3 Drive the API directly — `tools/mc101fw.py`

For anything the CLI does not cover (adding entries, resizing, synthesising a
whole member). The shape is always the same:

```python
import sys; sys.path.insert(0, "tools")
import mc101fw as fw

raw = fw.load_container("mc101_sys_v182.zip")   # accepts .zip or raw .bin
members = fw.parse_tar(raw)

out = []
for m in members:
    data = m.data
    if fw.is_qspi(data) and "C1C" in m.name:     # or C1A / C0C
        img = fw.parse_qspi(data)
        for e in img.entries:
            if e.name.strip() == "qspi_ver_def.h":
                e.data = open("my_qspi_ver_def.h", "rb").read()
                e.size = len(e.data)
        data = fw.build_qspi(img)
    out.append(fw.TarMember(name=m.name, size=len(data), offset=0, data=data,
                            mode=m.mode, uid=m.uid, gid=m.gid, mtime=m.mtime,
                            uname=m.uname, gname=m.gname))

open("MC101_UPA_up.bin", "wb").write(fw.build_tar(out))
```

Carry **every** metadata field through (`mode`, `uid`, `gid`, `mtime`, `uname`,
`gname`) or the rebuild stops being byte-exact. `tools/patch.py` is a 40-line
reference implementation of exactly this loop.

---

## 6. Worked examples: several test custom firmwares

Each example is self-contained and produces one image plus a stated expected
diff. Set up a scratch directory first:

```sh
mkdir -p build
```

### FW-1 — "marker" build: 3-byte text edit in the secondary MCU's `C1C`

```sh
make candidate   # see §5.1
```

* Change: `qspi_ver_def.h` inside `RPG69_C1C_up.bin`: `0.039` → `9.999`.
* Expected diff: **exactly 3 bytes**, first at `0x109e054`, container length
  unchanged at 20,285,440 B.
* Why start here: same size, plaintext entry, no offset moves, nothing whose
  format is unknown. This is the smallest image that still exercises the full
  path (tar header → member → entry table → payload).

### FW-2 — secondary-MCU "custom banner": edit a debug string in `idm1.bin`

The secondary MCU ships with a debug shell full of strings, e.g. `Legato HC
Reset Failer! %d` at `idm1.bin+0x8640`. Replace the same number of bytes:

```sh
W=/tmp/rev101/usages; mkdir -p "$W"
python3 - "$W/idm1_test.bin" <<'PY'
import sys
src = "firmware/raw/v182/RPG69_C1A_up_entries/idm1.bin"
d = bytearray(open(src, "rb").read())
old, new = b"Legato HC Reset Failer! %d", b"Legato HC Reset Custom! %d"
assert len(old) == len(new)
i = d.find(old)
assert i >= 0 and d.find(old, i + 1) == -1, "need exactly one occurrence"
d[i:i + len(old)] = new
open(sys.argv[1], "wb").write(bytes(d))
print(f"patched {len(old)} bytes of {len(d):,} at {i:#x}")
PY

python3 tools/patch.py --base mc101_sys_v182.zip --out build/MC101_UPA_idm1.bin \
  --replace RPG69_C1A_up.bin:idm1.bin:"$W/idm1_test.bin"
```

Output (verified):

```
patched 26 bytes of 241,796 at 0x8640
  replace RPG69_C1A_up.bin:idm1.bin 241,796 B -> 241,796 B  (sha 80f062ac8d050fbf -> 0c98743865d14ae4)
wrote build/MC101_UPA_idm1.bin  (20,285,440 B, sha256 b66274d8f2c07d88fe0928a405fe1694)
diff vs base: 6 bytes differ, first at 0xb60450
```

* Expected diff: **6 bytes** (`Failer` → `Custom`; the trailing `!` is
  unchanged), the entry size field and all offsets untouched.
* Why this one: it is a *real* code/data change inside a plaintext ARM image,
  still length-preserving, so any regression in the container path shows up as
  extra diff bytes rather than as a broken image.

### FW-3 — add a brand-new QSPI entry (custom payload slot)

The device looks entries up by name, so a new 16-byte-named payload dropped
into free space is the smallest "added functionality" that is still a valid
container. Free space is found after the last payload; offsets must stay
0x1000-aligned.

```sh
python3 - <<'PY'
import sys; sys.path.insert(0, "tools")
import mc101fw as fw

raw = fw.load_container("mc101_sys_v182.zip")
payload = b"REV101-CUSTOM-MARKER\n" * 4          # 84 bytes
out = []
for m in fw.parse_tar(raw):
    data = m.data
    if fw.is_qspi(data) and "C1C" in m.name:
        img = fw.parse_qspi(data)
        end = max(e.offset + e.size for e in img.entries)
        new_off = (end + 0xFFF) & ~0xFFF          # next 0x1000 boundary
        print(f"last payload ends {end:#x} -> new entry at {new_off:#x}")
        img.entries.append(fw.QspiEntry(name="rev101_test.bin", offset=new_off,
                                        size=len(payload), crc=0, ext=0,
                                        data=payload))
        data = fw.build_qspi(img)
    out.append(fw.TarMember(name=m.name, size=len(data), offset=0, data=data,
                            mode=m.mode, uid=m.uid, gid=m.gid, mtime=m.mtime,
                            uname=m.uname, gname=m.gname))
image = fw.build_tar(out)
open("build/MC101_UPA_extra_entry.bin", "wb").write(image)
d = [i for i in range(len(raw)) if image[i] != raw[i]]
print(f"wrote build/MC101_UPA_extra_entry.bin ({len(image):,} B), {len(d)} bytes differ")
PY

python3 tools/mc101fw.py build/MC101_UPA_extra_entry.bin   # re-parses your own output
```

Verified output:

```
last payload ends 0x14707b -> new entry at 0x148000
wrote build/MC101_UPA_extra_entry.bin (20,285,440 B), 103 bytes differ
...
        qspi_ver_def.h           off=0x0147000 size=       123 crc=0x00005235
        rev101_test.bin          off=0x0148000 size=        84 crc=0x00000000
```

* Diff = 84 payload bytes + the new 32-byte entry header (name/offset/size
  fields) + the entry-count field `0x10 -> 0x11`. The member size is unchanged
  (the payload lands in zero padding).
* Expected entry count: **17**. Both the tar member size and the C1C image size
  stay at 4,194,144 B, so nothing downstream shifts.
* Not yet proven: whether the device's loader (`FUN_01123bf0`) tolerates a
  count it did not ship with. Treat it as an experiment, and see FW-1/FW-2 for
  images that stay inside known-good structure.

### FW-4 — resize an existing entry (grow a 64-byte metadata blob)

`wromInfo_KY022.b` occupies `0x1000`..`0x1fff` in `C1C`; the next entry starts
at `0x2000`, so it can grow up to one full 0x1000 block without moving anything.

```sh
python3 - <<'PY'
import sys; sys.path.insert(0, "tools")
import mc101fw as fw

raw = fw.load_container("mc101_sys_v182.zip")
new_payload = bytes(range(256)) * 2 + b"\x00" * 44      # 556 bytes
out = []
for m in fw.parse_tar(raw):
    data = m.data
    if fw.is_qspi(data) and "C1C" in m.name:
        img = fw.parse_qspi(data)
        e = next(x for x in img.entries if x.name.strip() == "wromInfo_KY022.b")
        print(f"{e.name.strip()}: {e.size} B at {e.offset:#x} "
              f"(next entry at {img.entries[1].offset:#x})")
        e.data, e.size = new_payload, len(new_payload)
        data = fw.build_qspi(img)
    out.append(fw.TarMember(name=m.name, size=len(data), offset=0, data=data,
                            mode=m.mode, uid=m.uid, gid=m.gid, mtime=m.mtime,
                            uname=m.uname, gname=m.gname))
image = fw.build_tar(out)
open("build/MC101_UPA_grown.bin", "wb").write(image)
print("bytes differ:", sum(1 for i in range(len(raw)) if image[i] != raw[i]))
PY

python3 tools/mc101fw.py build/MC101_UPA_grown.bin | grep wromInfo
```

Verified:

```
wromInfo_KY022.b: 64 B at 0x1000 (next entry at 0x2000)
bytes differ: 512
        wromInfo_KY022.b         off=0x0001000 size=       556 crc=0x00000203
```

* The entry's declared `size` is rewritten to 556 and the payload extends into
  the entry's own 0x1000 sector; `crc` is carried through stale, as documented.
* **Hard constraint:** never let a grown payload reach the next entry's
  `offset`. If it must, rewrite the following entries' offsets too and keep
  them 0x1000-aligned — the device indexes by the table, not by `size`.
* Shrinking is the same operation in reverse; the old tail bytes stay in the
  buffer (that is deliberate, `build_qspi` reconstructs from the original).

### FW-5 — replace the whole secondary-MCU application set in one build

Both ARM images in `C1A` at once. This is the shape of a genuine custom
secondary-MCU firmware: you link two images and drop them in.

```sh
W=/tmp/rev101/usages
python3 - "$W/sdram1_test.bin" <<'PY'
import sys
d = bytearray(open("firmware/raw/v182/RPG69_C1A_up_entries/sdram1.bin", "rb").read())
print("size", f"{len(d):,}", "byte@0x100:", hex(d[0x100]), "-> 0x00")
d[0x100] = 0x00
open(sys.argv[1], "wb").write(bytes(d))
PY

python3 tools/patch.py --base mc101_sys_v182.zip --out build/MC101_UPA_both.bin \
  --replace RPG69_C1A_up.bin:idm1.bin:"$W/idm1_test.bin" \
  --replace RPG69_C1A_up.bin:sdram1.bin:"$W/sdram1_test.bin"
```

Verified:

```
  replace RPG69_C1A_up.bin:idm1.bin 241,796 B -> 241,796 B  (sha 80f062ac8d050fbf -> 0c98743865d14ae4)
  replace RPG69_C1A_up.bin:sdram1.bin 3,709,724 B -> 3,709,724 B  (sha e532f514f64f3181 -> a99669f1d54dd10a)

wrote build/MC101_UPA_both.bin  (20,285,440 B, sha256 446aa81aec8f20d48e19b4e187e9837f)
diff vs base: 7 bytes differ, first at 0xb60450
```

* Expected diff: 6 (idm1 string) + 1 (sdram1 byte) = **7 bytes**.
* Requirements for a *real* replacement, from the decompiled loader:
  payloads must be **raw, uncompressed bytes**, and the `0x1c`-byte per-entry
  descriptor the loader fills must still satisfy its
  `base pointer = stored + file_base` expectation. See
  [SECONDARY_MCU.md](SECONDARY_MCU.md) and [FINDINGS.md](FINDINGS.md) §8.3.

### FW-6 — synthesise a QSPI member from scratch (fallback path)

`build_qspi` uses the original image bytes as its base. If you build an
`QspiImage` with no `original` attribute, you get the zero-filled fallback:
correct magic/table/offsets, but the 1..~30-byte tails after each entry are
zeroed. Useful to prove a format hypothesis; **not** a good basis for a
flashable image.

```sh
python3 - <<'PY'
import sys; sys.path.insert(0, "tools")
import mc101fw as fw

entries = [fw.QspiEntry(name="hello.bin", offset=0x1000, size=18, crc=0, ext=0,
                        data=b"REV101!!!" * 2)]
img = fw.QspiImage(prefix=bytes(0x30), entry_base=0x30, entry_count=1,
                   entries=entries)
blob = fw.build_qspi(img)
print("size", len(blob), "is_qspi", fw.is_qspi(blob))
print("entries:", [(e.name, hex(e.offset), e.size)
                   for e in fw.parse_qspi(blob).entries])
PY
```

Verified:

```
size 8192 is_qspi True
entries: [('hello.bin', 0x1000, 18)]
```

---

## 7. Verify a custom image

Every example above should be checked the same way. In order of strength:

```sh
# 1. your own output must re-parse with the expected table
python3 tools/mc101fw.py build/MC101_UPA_up.bin

# 2. the diff must be exactly what you intended — no collateral drift
python3 - <<'PY'
import sys; sys.path.insert(0, "tools")
import mc101fw as fw
a = fw.load_container("mc101_sys_v182.zip")
b = open("build/MC101_UPA_up.bin", "rb").read()
d = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
print("bytes differ:", len(d), "first:", hex(d[0]) if d else None,
      "span:", hex(d[-1] - d[0] + 1) if d else None)
print("length:", f"{len(a):,}", "->", f"{len(b):,}")
PY

# 3. the raw byte diff, if you want to eyeball it
cmp -l mc101_sys_v182.zip build/MC101_UPA_up.bin | wc -l   # note: this is the ZIP, see §8

# 4. "is my change still confined to the entry I meant?"
python3 tests/test_patch.py     # the tooling's own confinement test
```

For a same-size edit the container length **must not change**
(20,285,440 B) and the diff must be confined to the target payload's byte
range (`tests/test_patch.py` asserts exactly this for the 3-byte marker edit:
`all changed bytes inside target payload [0x109e000, 0x109e07b)`).

**What this does not prove:** the entry `crc32` is not recomputed and does not
validate against the payload, so these checks confirm *structure*, not
*integrity as the device defines it*. That gap is [FINDINGS.md](FINDINGS.md)
§8.1.3 and it is the last open item in the container work.

## 8. Package it the way Roland ships it

Roland ships `mc101_sys_v182.zip` containing
`mc101_sys_v182/MC101_UPA_up.bin` (deflate; the zip member name includes the
version directory). `fw.load_container()` accepts either the zip or the bare
`MC101_UPA_up.bin`, so for tooling you can stay with the raw file; if the
updater matches on name/layout, mirror it:

```sh
python3 - <<'PY'
import shutil, zipfile, pathlib
v = "182"
d = pathlib.Path(f"/tmp/rev101/usages/repack/mc101_sys_v{v}")
d.mkdir(parents=True, exist_ok=True)
shutil.copy("build/MC101_UPA_up.bin", d / "MC101_UPA_up.bin")
with zipfile.ZipFile(f"/tmp/rev101/usages/repack/mc101_sys_v{v}.zip", "w",
                     zipfile.ZIP_DEFLATED) as zf:
    zf.write(d / "MC101_UPA_up.bin", f"mc101_sys_v{v}/MC101_UPA_up.bin")
PY
python3 tools/mc101fw.py /tmp/rev101/usages/repack/mc101_sys_v182.zip   # sanity check
```

## 9. Read the plaintext MCU (optional, but this is where the answers are)

Only the secondary-MCU images are fully readable, and only GHIDRA-based work
needs a Ghidra install:

```sh
make ghidra        # analyse idm1.bin (base 0x01100000) + sdram1.bin (0x01000000)
make decompile     # decompile every recovered function
```

Outputs (default `GHIDRA_WORK=/tmp/rev101`, override with the env var):

```
/tmp/rev101/idm1.bin.ghidra.txt       FUNC <addr> <name> size=<n> lines
/tmp/rev101/sdram1.bin.ghidra.txt
/tmp/rev101/idm1.bin.decompall.txt    1,062 functions, greppable C
/tmp/rev101/sdram1.bin.decompall.txt  2,069 functions
```

One function on demand:

```sh
GHIDRA_WORK=/tmp/rev101 tools/ghidra_decompile.sh sdram1.bin 0x01075972
```

These files already exist in `/tmp/rev101` on this machine, so the grepping in
[SECONDARY_MCU.md](SECONDARY_MCU.md) can be reproduced without re-running
Ghidra. Ghidra needs a writable `$HOME/.config`, which is why the scripts
redirect `HOME`/`XDG_*` into `GHIDRA_WORK`.

The open questions that Ghidra work is chasing:
the covered range of the entry `crc32`, and the `PRJ5` record schema inside
`init.lzs` (4-bit-framed, not compressed, so there is no `.lzs` decompressor to
find). The entry-base arithmetic in `FUN_01123bf0` is now reconciled — see
[FINDINGS.md](FINDINGS.md) §8.1.1.

## 10. What is not possible yet

| you cannot… | blocked by |
|---|---|
| change anything inside the `C0A` main-CPU application | 1.1 MB incompressible window `0x0c0000`–`0x1d0000`, mechanism undetermined ([FINDINGS.md](FINDINGS.md) §4) |
| decompress / modify `init.lzs` (the application runtime) | framing `[data][0xXf]` confirmed and names readable (`tools/unlzs.py`); the PRJ5 field-level record schema is unresolved ([FINDINGS.md](FINDINGS.md) §6) |
| confirm a modified image is internally consistent to the device | entry `crc32` algorithm known (CRC-32) but covered range unknown (§8.1.3) |
| know whether the bootloader accepts a repacked image | first-stage bootloader not present in these four members (§8.4) |
| flash anything | by design: this repository only writes files |

The realistic target today is the **secondary MCU** (`C1A` →
`sdram1.bin`/`idm1.bin`): plaintext, symbol-rich, raw-consumed, no
cryptography. See the recommended work order in
[FINDINGS.md](FINDINGS.md) §8.3.

## 11. Rough edges worth knowing

* `patch.py`'s docstring advertises no `--replace-in-place` flag; an in-place
  same-size edit is just a `--replace` whose file has the original length.
* `--replace` matches `MEMBER` as a substring: `C1A` is convenient, but be
  aware it is not an exact-name match.
* The `crc32` in an entry table is never recomputed (see §7).
* `describe()`'s one-line C0A summary prints `load_off=0x0 load_addr=0xc0040`;
  `load_off` is the value stored in the C0A header (the fields are big-endian
  32-bit). Trust the parsed output and the hexdump if a comment ever disagrees.
* Adding entries (FW-3) changes the entry count — valid container, unproven on
  hardware.
* `idm1.bin`/`sdram1.bin` are identical across v1.80–v1.82, so cross-version
  swaps of those entries are no-ops.
* Ghidra paths in `tools/*.sh` are machine-specific
  (`/home/emilio/ghidras/ghidra_11.3.2_PUBLIC`); set `GHIDRA=` elsewhere.

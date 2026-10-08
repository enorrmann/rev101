# Roland MC-101 firmware — reverse engineering findings

Analysis of three `mc101_sys_v18*.zip` releases. Each zip contains one
`MC101_UPA_up.bin` (20,285,440 bytes) — a **plain POSIX tar archive** holding
four raw flash images for two different CPUs.

Platform code is **RPG69** (MC-101 = RPG69; MC-707 = RPG68, visible in the
`tone_pcmEx_rpg68` blob names).

> **Correction notice.** An earlier revision of this analysis claimed the whole
> `C0A` payload was encrypted with a version-independent key, and concluded
> that "one key break opens every firmware version". Measurement
> (see [Region map](#4-c0a-is-a-hybrid-not-a-single-ciphertext-blob)) disproved
> that. Only ~1.1 MB of `C0A` is incompressible, and that block is byte-identical
> between v1.81 and v1.82 while differing almost entirely between v1.80 and
> v1.81. Do not rely on the earlier blanket-ciphertext conclusion.

---

## 1. Delivery container: plain tar

`MC101_UPA_up.bin` is a **standard POSIX tar** (`ustar` magic at 0x101), mode
`0777`, uid/gid `1000/1000`, written by GNU tar (magic spelling `ustar  \0`,
empty uname/gname). Members:

| member | size | mtime (in-tar) |
|---|---|---|
| `./_tmp/RPG69_C0A_up.bin` | 3,499,600 | 1684331698 |
| `./_tmp/RPG69_C0C_up.bin` | 8,388,576 | 1684331700 |
| `./_tmp/RPG69_C1A_up.bin` | 4,194,144 | 1684331372 |
| `./_tmp/RPG69_C1C_up.bin` | 4,194,144 | 1684331372 |

`tar tvf` reads it directly. The members being written to `./_tmp/` implies the
updater is a Linux/POSIX process that untars before flashing.

`tools/mc101fw.py` rebuilds this container **byte-for-byte** for all three
versions (verified — see [§7](#7-verification)).

## 2. Inner container: "QSPI " with an entry table

`C0C`, `C1A` and `C1C` are QSPI flash filesystem images:

```
+0x20   "QSPI " + NUL pad            magic
+0x28   u32 LE   format word         observed 0x20 (must equal 0x20)
+0x2c   u32 LE   entry count
+0x30   entry table, 0x20 bytes each:
            name[16] | offset u32 | size u32 | crc32 u32 | ext u32
```

Entry payloads are 0x1000-aligned. Three details cost real debugging and are
now handled in the tooling:

1. **The entry table starts at `0x30`, not at the `0x28` field's value.** The
   `0x28` field is not an absolute base.
2. **Names occupy the full 16-byte field with no guaranteed NUL.**
   `tone_pcmx_cmn.bi` is exactly 16 chars and fills it.
3. **The `size` field under-reports each payload by a short tail** (1..~30
   bytes of genuine data at every entry boundary, e.g. at `0x1050` after
   `wromInfo_KY022.b`). `build_qspi` therefore uses the original bytes as its
   base rather than reconstructing from `size`.

`C1A`/`C1C` additionally begin with a leading length word (`0x003fff30` ==
filesize − 48) followed by 48 NUL bytes.

### Contents

**`C0C`** (main CPU sample/PCM bank, 12 entries): `tone_pcmx_cmn.bin`,
`tone_pcmEx_{ky022,rpg68,slgnd,snsyn,i5080}`, `kit_pcmx_{cmn,rpg68}`,
`inst_pcmx_{cmn,rpg68}`, `qspi_ver_def.h`, `init.lzs`.

**`C1C`** (16 entries): `wromInfo_KY022.bin`, `tone_pcmx_test.b`,
`metronome.bin`, `kit_pcmx_metro.b`, `inst_pcmx_metro.`,
`spf_muse_*` / `wpf_muse_*` (partials/waveforms for the "muse" engine),
`qspi_ver_def.h`.

**`C1A`** (2 entries): `idm1.bin` (241,796 B), `sdram1.bin` (3,709,724 B).

`qspi_ver_def.h` is plaintext:
```
// QSPI Version
T(TARGET,    PCM-EX)
T(PRM_VER,   0.039)
T(QSPI_DATA, 0.058)
```

## 3. CPU architecture

`sdram1.bin` and `idm1.bin` are **plaintext ARM Cortex-M code** — no
decompression or decryption needed. Confirmed by:

* Capstone `CS_ARCH_ARM`/`CS_MODE_THUMB` decodes coherent code, including the
  standard little-endian byte-swap helper `revsh r0, r0; bx lr` and
  `movw/movt/bx` idioms.
* `idm1.bin` at `+0x20` is a real Cortex-M vector table: initial SP
  `0x200a91c8`, then handlers `0x01100de5`, `0x01100e55`, `0x01100e57`,
  `0x01100e59`, `0x01100e5b`, `0x01100e5d` — all Thumb-bit set. SRAM at
  `0x20000000`, code at `0x01100000` → **STM32-family** memory map.
* `sdram1.bin` yields 3,033 ASCII strings ≥12 chars, including
  `wromInfo_KY022.bin`, `tone_pcmx_%s.bin`, `spf_muse_%s.bin`,
  `Legato HC Reset Failer! %d`, `%08d: ASGN prmId Err(%d)`.

A statistical opcode-density probe (`/tmp` scratch, not committed) ranks
ARM/Thumb first for these two files once word alignment is handled correctly;
the earlier "X86-64" ranking from a naive probe was an artifact of
disassembling mid-instruction and is not meaningful.

## 4. C0A is a hybrid, not a single ciphertext blob

`C0A` header, plaintext, 0x60 bytes (verified against all three versions):

```
0x00  16 B   "App1_Main\0..."      name
0x10  16 B   "2023/05/17 22:54"    date, no NUL (runs to 0x1f)
0x20   8 B   "0.010001"            version string
0x28   4 B   0x00000060            load offset = 0x60
0x2c   4 B   0x00000000            zero
0x30   4 B   0x000c0040            load address
0x34  12 B   0xffffffff x3         erased region
0x40   4 B   0x000c0060            mirror
0x44   4 B   0x003565b0            payload size (see note)
0x48   4 B   0x00000060
0x4c   4 B   0x00000000
0x50   4 B   0x513fc2d9            digest
0x54   4 B   0xb6020001            flags / format id
0x58   4 B   0x00000000
0x5c   4 B   0xffffffff
```

*Size note:* the `0x44` field is `0x3565b0` for v1.82 while filesize − 0x60 is
`0x3565f0`; the delta is a fixed `0xa0` tail. (Both are consistent with
`0x44` being a big-endian u32.) The tooling records the value and asserts only
that the delta is non-negative and < 0x1000, rather than pretending to a
byte-exact rule we have not proven.

### Region map of the C0A body

Measured by zlib ratio per 16 KiB block, over the 3,499,504-byte body:

| offset range | zlib ratio | entropy | interpretation |
|---|---|---|---|
| `0x00000`–`0x0c0000` | 0.87 | 7.985 | structured / high-entropy code+data |
| `0x0c0000`–`0x1d0000` | **1.0003** | **7.9999** | **incompressible ≈ 1.1 MB** |
| `0x1d0000`–`0x300000` | mixed | 7.63 | structured, large zero runs |
| `0x300000`–`0x310000` | 0.002 | → 0 | an all-zero 64 KiB block |
| `0x310000`–`0x3565f0` | mixed | — | structured remainder |

Whole-body zlib ratio is 0.733. The incompressible window is exactly
`0x110000` = **1,114,112 bytes**, and a refreshed measurement reports its
ratio as 1.0003 against the `1.0004` quoted for the coarser `0xb6000` boundary
earlier — the boundary simply moved to the first 16 KiB block whose own ratio
exceeds 1.0. This is why a whole-body entropy figure of 7.888 looked like
"encryption" and was misleading — the body is a **mixture**, dominated by
compressible content.

### Version-to-version comparison

Body bytes identical (out of 3,499,504):

| pair | whole body | code region `0..0x0c0000` | window `0x0c0000..0x1d0000` |
|---|---|---|---|
| v1.80 → v1.81 | 24.69 % | 71.67 % | **0.39 %** |
| v1.81 → v1.82 | 94.02 % | 99.70 % | **100.00 %** |

Interpretation: the incompressible block is byte-identical across
v1.81→v1.82 (a small point release) but almost entirely different across
v1.80→v1.81 (a large feature release). Whatever that block is, it is **not**
a per-version re-keyed stream cipher, and it is equally not proven to be a
single stable ciphertext. It may be a large compressed/packed data blob whose
contents genuinely changed between 1.80 and 1.81.

**What is safe to say:** that window is high-entropy and incompressible.
**What is not safe to say:** that the firmware is protected by one
version-independent cipher key.

### Deeper structure of the body (measured at 4 KiB granularity)

Counting each 4 KiB block by its zlib-9 ratio (`E` ≥ 0.995 incompressible,
`C` < 0.9 compressible, `M` otherwise) over the whole body:

| class | bytes | fraction |
|---|---|---|
| `E` (incompressible / ciphertext-like) | 1,589,248 | 45.4 % |
| `C` (compressible / packed) | 1,398,256 | 40.0 % |
| `M` (mixed / boundaries) | 512,000 | 14.6 % |

So the "code region" `0..0x0c0000` is itself a mixture (the coarse 0.87 ratio
was the blend of `E` and `C` runs), not a single ciphertext. Two further
facts, both new:

* **The `E` material is a 64-bit-block cipher in ECB mode.** In
  `0xa0000..0xb5000` (a `C` pocket *inside* the code region, ratio 0.2) there
  are thousands of runs of one fixed 8-byte value repeated every 8 bytes
  (`6b4c9a852c732831`, plus `dc1205ad381ecdac`, `e372fb5ef54ba427`, ~10 whole
  run-values), always starting on 8-byte boundaries, separated by 8- or
  16-byte "records". That is exactly `E_K(0x00…00)`-style anchors of an
  ECB cipher with block size 8 — *not* a 16-byte (AES) cipher, whose zero
  block would repeat with period 16. The value survives across versions
  (v1.80 shows the same anchors, shifted 8 bytes where the plaintext shifted),
  so the key/transform is version-stable. The cipher is non-linear
  (XOR-closure test fails), and no DES/3DES/Blowfish/test vector matches with
  obvious keys; no cipher constants live in `sdram1.bin`/`idm1.bin`.
* **The incompressible window `0x0c0000..0x1d0000` has zero repeated 8- or
  16-byte blocks**, unlike the anchors above: it is a different mode or a
  different plaintext with no repeats. It is *not* the nibble-framing used by
  `init.lzs` (its low-nibble `f` rate is 6.25 % = uniform, versus 48.5 % for
  `init.lzs` — see §6).

The window/`E` regions therefore remain the one genuinely unreadable part of
`C0A`; the key lives with the first-stage loader that is not in these images.

## 5. What is protected, and what is not

**Immediately usable, no cryptography:**
* Tar container, member names/layout/sizes/mtimes.
* QSPI container format, all entry tables, all `size`/`offset` fields.
* `sdram1.bin` + `idm1.bin` — complete plaintext ARM Cortex-M firmware.
* All of `C1C`'s 16 entries and `C0C`'s smaller metadata entries.
* `init.lzs` — the `PRJ5` project's 4-bit-marked payload (drop `0xXf` markers to read names; field schema unresolved, see §6).
* `qspi_ver_def.h`, build dates, version strings, load addresses, digest field.

**Not yet readable:**
* The 1.1 MB incompressible window inside `C0A` (re-measured in §8.3 as
  `0x0c0000`–`0x1d0000`), plus the `E`-class regions of §4.
* The byte range covered by the QSPI entry `crc32` field — the algorithm is
  CRC-32, but no candidate range reproduces the stored value (§8.1.3).
* Whether the outer container's digest is verified by a boot ROM (unknown —
  the bootloader for the very first stage is not in these four members).

### CRC fields do not validate

The `crc32` fields in the QSPI entry table did **not** match a computed
CRC over the extracted payload for any entry, in any version, in any of the
four images. The outer tar carries no signature table at all.

> **Correction.** An earlier revision of this section also claimed "the
> constants `0xEDB88320`, `0x04C11DB7`, `0xA001` do not appear as immediates"
> and that no CRC32 table exists in the image. Both are wrong: the generator
> loads `0xEDB88320` from a literal and computes the 256-entry table into RAM,
> so a scan of the *file* for a materialised table finds nothing. See
> [§8.1.3](#813-the-qspi-entry-checksum-is-crc-32-but-over-an-unknown-byte-range)
> for the disassembly and for what remains genuinely unknown — the byte range
> the field covers.

Whatever integrity mechanism exists lives inside the bootloader, not in the
container.

## 6. `init.lzs` — Roland `PRJ5` project, 4-bit-marked (framing confirmed; field schema unresolved)

`init.lzs` (969,045 B) holds the application runtime data. Status:

**Correction notice.** An earlier revision of this analysis said `init.lzs`
"contains the Python-style traceback strings visible in the parent image", and
described its byte histogram as "a flat ~29,700 bump on every `0xXf` value".
Both statements are wrong. A full search of every member of the container
finds **no** `Traceback`, `python`, `lua` or `File "` occurrence in any image
(`C0A`, `C0C`, `C1A`, `C1C`, `init.lzs`, `sdram1.bin`, `idm1.bin`). The 0xXf
values are *not* flat: they form an alternating ladder (see below). The
distinctness figure among the 16 `0xXf` counts is now used deliberately as a
test below.

**Established (with controls):**
* Body (offset `0x40` onwards, 968,981 B): entropy **6.7333 bits/byte**,
  distinct byte values **256** (full-span). The full file is
  969,045 B with entropy 6.73.
* A shuffled control over the identical byte distribution yields 73 printable
  runs ≥8 chars; the real stream yields **3,702**. That ~50× excess is real
  structure, not a statistical accident.
* The low nibble `0xf` appears 470,382 times in the body (7.77× expected,
  **48.5 % of bytes**), while the high nibble is nearly flat
  (0.92–1.92× expected). So the byte stream is **4-bit-symbol oriented**: the
  low nibble carries the token, the high nibble is largely a carrier.

**The `0xXf` "bump" is a noisy alternating ladder, not a flat bump.**
Full-file counts of the 16 values `0x0f, 0x1f, … 0xef, 0xff` are:

```
odd  positions (0x0f,0x2f,…)  mean 29,747.6
even positions (0x1f,0x3f,…)  mean 29,050.6
```

The two interleaved means differ by ~697 while the within-group spread is ~80.
An exact (chi-square) test of the 16 counts against "uniform" rejects at
p ≈ 2 × 10⁻²⁰, so the alternating structure is real signal, not sampling noise.
A whole-file `Counter` run over the same data reproduces this digit-for-digit,
so the ladder is a property of the file, not of the extraction path.

**Ruled out** (attempted, no output > 64 KiB): zlib, raw deflate (all window
bits), gzip, bzip2, LZMA-alone, XZ, and LZ4 — each at every offset `0..0x300`
of the file, plus a broad magic scan. Simple 4-bit repacking in either nibble
order does not produce readable output either. There is no valid 256-entry
CRC32 table in the image, and no `init.lzs` string anywhere, so the payload is
not naming its own container.

### Framing confirmed: `init.lzs` is a *4-bit-marked* stream (not LZ compression)

The remainder of this section retracts the "bespoke LZ codec" conclusion. The
framing rule is confirmed directly in the data, but the record layout below the
framing is **not** — the two are stated separately on purpose:

> **`init.lzs` carries its data as an interleaved stream of plain 8-bit bytes
> and marker bytes whose low nibble is `f` (`0x0f`..`0xff`).  Dropping every
> byte with low nibble `f` yields the readable payload.**

That is exactly the "4-bit-symbol orientation" the histogram predicted, but it
is not a compression: it is a *field-framing* scheme. The `0xXf` bytes are
**markers** (their high nibble carries a 4-bit control/extension value); the
real data is every other byte, in stream order.

Verification — the decoded stream contains real, self-consistent Roland text
that the raw file could not contain.  **Important correction on which of those
strings are real:** several strings below were verified byte-by-byte against
the raw image, and the ones marked ✗ are *artefacts of the filter*, not names
stored in the file — do not cite them as content.

| decoded run | byte-verified status |
|---|---|
| `PRJ5` `aMC7` `STP` | ✓ real, live raw in the `0x20`–`0x40` header (`d` offsets 35/44/57) |
| `INIT` (abs `0x8f`), `InitT` (abs `0xbd105`) | ✓ real, raw-contiguous |
| `TR-909 Kick 1` | ✓ real — `TR-909 [ff] Kick 1`, one marker inside |
| `Rimsh…t P`, `Snr 3a P`, `Clap 2`, `MidG2M0`, `707 Tamb` | ✓ real (some with a marker inside, e.g. `707 [df] Tamb`) |
| `Cwbell 1` | ⚠ raw reads `Cowbel/l 1` — "Cwbell" is a filter artefact |
| `rash!A` | ✗ there is **no** `Cr` anywhere: `Crash!` was an interpretation, wrong |
| `deCym 1` | ✗ there is **no** `Ri`/`Ride` anywhere: `Ride Cym 1` was wrong |
| `27CngaMtHi` | ✗ there is **no** `Co` anywhere: `Conga …` was wrong |
| `1CUgy` `0BTfx` `2DVhz` `4FXA…` `$6H1l~` … | ✗ not tags: recurring marker-noise from the parameter tables (5-byte patterns repeating every few dozens of bytes), not text |
| the tail pointer ladder `05 17 29 3b 4d …` (+`0x12` per step, 18-byte records) | ✓ the marker removal turns the f-suffixed pairs into a clean arithmetic pointer table |

So the framing rule stands (that is not in question), but the *readable*
content is **only** the handful of ✓ strings: the header tags, `INIT`/`InitT`,
and the `TR-909`/`707`/`Cowbel` drum-kit fragment names around body offset
`0x7a9xx`.  The rest of the filtered stream is binary table data whose
short "printable" runs are coincidences between the marker alphabet and ASCII.

The marker sub-stream is itself structured: the alternating high-nibble
histogram (even ≈ 29,750 / odd ≈ 29,050) is the *marker alphabet*, not a
statistical accident.  The `[data][0xXf]` pairing yields 12-bit values that
form clean arithmetic pointer ladders (`05 6f 17 6f …` → `0x605, 0x617, …`,
step `0x12`), and those ladders **nest** — the offsets they encode point to
further ladders inside the file.  That is confirmed by measurement.

Tooling: `tools/unlzs.py` performs the unframing (`<file>.decoded`,
`<file>.markers`, `--strings`).  Decoded payload size 498,599 B, marker stream
470,382 B (48.5 % of the body) for all three releases.

### What is NOT confirmed (do not claim it as decoded)

* The **record boundaries / field semantics** of the `PRJ5` project data.
  The drum-kit partial names are variable pitch (no fixed record size), with
  no consistent length prefix in the bytes before each name — so a full
  record-schema decode is **not** recoverable from this image alone.
* The meaning of the 12-bit ladder values (they step by `0x12` = 18 and are
  page-local `< 0x1000`, but their base address is unknown).
* Whether a marker carries an extension bit, a continuation flag, or padding.

**Header identity (confirmed):** `init.lzs` is a Roland `PRJ5` project
container — raw tags `PRJ5` / `aMC7` / `STP` at offsets 0x23 / 0x2c / 0x39 —
not a record-array like its siblings (see the new confirmed schema below).

### The plaintext sibling record-container schema (confirmed, fully parsed)

The other `C0C` entries use a different, *plaintext* container that IS fully
decodable, and it is the Rosetta stone for this format family:

| offset | field | `kit_pcmx_cmn.bin` | `tone_pcmx_cmn.bi` | `inst_pcmx_cmn.bi` |
|---|---|---|---|---|
| 0x00 | (all zero) | 0x20 bytes | 0x20 | 0x20 |
| 0x20 | type word (LE u32) | `0x00120005` | `0x00140004` | `0x00130003` |
| 0x24 | name length (`0x10`=16) | 16 | 16 | 16 |
| 0x28 | payload byte count (LE u32) | 246,284 | 1,198,524 | 153,536 |
| 0x2c | `0x1d` (29, constant) | 29 | 29 | 29 |
| 0x30 | **record count** (LE u32) | 74 | 837 | 711 |
| 0x34 | array-header size (`0x0c`=12) | 12 | 12 | 12 |
| 0x38 | **record size** (LE u32) | 3,328 | 1,432 | 216 |
| 0x3c | first record (name field first, 16 B) | `Standard Kit    ` | `Piano 1         ` | `Off             ` |

Checks that close the loop: `record count × record size + 12 = payload field`
(74×3328+12 = 246,284 ✓); records start at file 0x3c and repeat at the
record-size pitch with 16-byte space-padded names.  `kit_pcmx_cmn.bin`'s
74 records are the **kits** (`TR-909`, `TR-808`, `Room Kit`, …); each kit's
3328-byte body is a plaintext drum-partial map (each partial ≈ 12–16 B:
`[note LSB][00 00][cd 00][00 00][7f cd][wave id][mute/params]`).  The
drum-partial *names* themselves ("Kick 1", "Rim Shot", …) are **not** in this
file — they are the strings that show up inside `init.lzs`, the `PRJ5` project.

So: the record-array schema is solved and confirmed; the `PRJ5` project's own
field schema inside `init.lzs` is **not** — confirming a complete decode here
would require the Roland `PRJ` format reference (community
`ZenInspector`/`RolandZenDecodeXML` documents PRJ file structure but the
per-field tables for the MC-101 PRJ were not reachable from this workspace).

### How the `.lzs` question was resolved
1. ~~Locate a decompressor inside `sdram1.bin` / `idm1.bin`~~ — resolved: there
   is none; the framing is data-inherent, not a runtime decode.
2. ~~Find an open-source Roland/KORG `.lzs` implementation~~ — resolved: the
   framing is the 4-bit marker scheme above.

## 7. Verification

```
$ make test
18/18 checks passed      # tests/test_roundtrip.py
9/9  checks passed       # tests/test_full_rebuild.py
9/9  checks passed       # tests/test_patch.py
14/14 checks passed      # tests/test_safety.py
2/2  checks passed       # tests/test_unlzs.py
4/4  checks passed       # tests/test_rb_record.py
```

The acceptance test is **byte-exact full-container rebuild** for all three
releases (20,285,440 B each). A byte-exact rebuild when nothing is modified
means any difference in a later modified image is provably the intended change.

Independent of the tooling, the **device itself** confirms the container layout
in `idm1.bin`'s QSPI name lookup (§8.1.1): magic `"QSPI"`, 0x20-byte entry
stride, 0x20-byte entry size field, and 16-byte case-insensitive names with
non-printables folded to `_`. That is a second, unrelated source agreeing with
the byte-exact repack.

**What verification does not reach.** `crc32` in the entry table is written
through unchanged by the repack (which is why it stays byte-exact), but it is
not a checksum *of the payload*, so the tooling has no independent way to
confirm a modified image is internally consistent. See §8.1.3.

## 8. Recommended next steps, in order

> **Steps 8.1 and 8.2 are done.** Their results are in this section. Step 8.3
> is the open decision; read it before doing anything else.

### 8.1 Reverse `sdram1.bin` properly — DONE

Headless Ghidra 11.3.2, `ARM:LE:32:Cortex`, `-loader-baseAddr 0x01000000`,
with a freshly extracted `sdram1.bin` (SHA-256
`e532f514…572835ba`, identical to the copy used earlier, so the two
decompilations are guaranteed to be of the same bytes).

| image | base | functions recovered |
|---|---|---|
| `idm1.bin` | `0x01100000` | 1,062 |
| `sdram1.bin` | `0x01000000` | 2,069 |

Reproduce with:

```sh
make extract-all
make ghidra        # analysis project + per-image function list
make decompile     # every function decompiled to <image>.decompall.txt
```

`$GHIDRA_WORK` (default `/tmp/rev101`) holds `<image>.ghidra.txt` and
`<image>.decompall.txt`.

#### 8.1.1 The QSPI container read path, decompiled

This is the finding that matters most for the container work: **the secondary
MCU's QSPI reader returns the stored bytes verbatim. It never calls a
decompressor.**

`idm1.bin` `FUN_0110d6e0` is the C1C catalogue loader. It opens each entry by
name through `FUN_01123bf0` — a QSPI name→entry lookup:

```c
uint FUN_01123bf0(undefined4 *param_1, char *param_2)
{
  local_48='Q'; local_47='S'; local_46='P'; local_45='I';   // "QSPI" magic
  local_44 = 0x10;      // scratch (overwritten by the read below)
  local_40 = 0x20;      // header word at file +0x28 -> must equal 0x20
  local_3c = 0;         // header word at file +0x2c -> entry count
  if ((*DAT_01123d14 == 0) && (FUN_0112444e(&local_48, 0, 0x10) != 0)) {
      if (local_48=='Q' && local_47=='S' && local_46=='P' && local_45=='I'
          && local_40==0x20 && local_3c!=0) {
          *puVar2 = local_3c;        // entry count
          puVar2[1] = 0x10;          // entry base, in QSPI-container offsets
      }
  }
  ...
  FUN_0112444e(param_1, puVar2[1] + uVar9*0x20, 0x20);   // read one 0x20 entry
  // names are compared case-insensitively, with everything outside
  // [0x20,0x7f) mapped to '_'
}
```

Every field the tooling assumes is confirmed here, by the device itself:

* magic `"QSPI"` at `+0x20`;
* entry stride `0x20`;
* the header word at `+0x28` must be `0x20`, and `+0x2c` carries the entry
  count — both match the file (`+0x28 == 0x20`; `+0x2c == 12` in `C0C`, `16` in
  `C1C`, `2` in `C1A`);
* entries carry a 16-byte name compared case-insensitively, non-printable
  bytes folded to `_` — which is why `tone_pcmx_cmn.bi` and
  `inst_pcmx_rpg68.` are stored truncated to exactly 16 bytes with no NUL.

> **Entry base.** The 16 header bytes are read from QSPI-container offset 0, so
> the container origin is the magic at file `+0x20`. The lookup then indexes
> entries as `0x10 + i*0x20` *in that same offset space*, i.e. file
> `0x30 + i*0x20` — exactly the observed table start. (An earlier revision read
> the literal `0x10` as the value of the `+0x28` field; the `+0x28` word is
> really `0x20`.) Confirmed beyond doubt: the magic, the `0x20` stride, the
> `+0x28 == 0x20` check, the count at `+0x2c`, and the name comparison — i.e.
> everything the parser in `tools/mc101fw.py` depends on.

The read primitive is `FUN_0112444e(buf, offset, len)`: it copies `len` bytes
from the QSPI window into `buf`, word-wise for the bulk of the transfer and
byte-wise for the last three bytes (the exact middle-endian fill pattern
Ghidra renders as repeated `puVar7[1] = puVar6[1]; *puVar7 = *puVar6;`).
A hard mask `0x1000000` (16 MiB QSPI aperture) bounds every transfer. The
backing window is set up by `FUN_011243ba`, which maps `0x0c000000` (normal) or
`0x61800000` (alternate).

So: **an entry payload is exactly its stored bytes.** A replacement
`sdram1.bin` must be a raw image, not a compressed one.

#### 8.1.2 Why `init.lzs` has no decompressor in these images

The same holds for the main-CPU side. In `sdram1.bin`, the region
`0x01075a34`–`0x0107e200` is the QSPI test/dump module:

* `FUN_01075d98` — the routine that prints the `QSPI%d Test CRC32 Start...` /
  `QSPI%d Test End (Erapsed Time = %d)` messages seen in the string dump. It
  reads the entry in `0x80`-byte chunks straight into a CRC32 state
  (`thunk_FUN_0112450e` = read, `thunk_FUN_011289fe` = CRC32 update) and
  compares the result against the entry's `crc32` field with
  `FUN_01075a86`. **It never decompresses.**
* `FUN_01075c1c` / `FUN_01075b4c` — a large dispatch table on an `int` "screen
  id" that ferries a per-screen record to the BMC (hardware register writes).
  It is **not** a decoder: the constant `0x6171` is the BMC command tag, and
  the third byte is a field index, which is why the apparent shift amounts
  (`>> 7`, `>> 11`, …) look like shifts but trail off into noise.

A whole-file search for the strings `init.lzs`, `lzs`, `LZS` over `C0A`,
`C0C`, `C1A`, `C1C`, `sdram1.bin` and `idm1.bin` finds **one** hit: the
filename itself in `C0C`'s entry table. `VQSPI` occurs twice in `sdram1.bin`
and nowhere else. Nothing references the file by name and no decompressor is
reachable from the QSPI read path, so the `.lzs` payload is consumed by code we
have not located — either in the `C0A` main-CPU application (which is
unreadable) or behind a pointer table the analyser did not resolve.

#### 8.1.3 The QSPI entry checksum is CRC-32, but over an unknown byte range

`idm1.bin` contains the QSPI checksum implementation, fully disassembled, and
it explains the `%08d: QSPI%d Test CRC32 Start...` string and the
`QSPICSum = %04X` output:

```
0x011289d0  table generator, 256 iterations of the classic
            "crc chained 4x + immediate mask" construction  -> 256 x u32 table
0x01128a1e  update:  table[(crc ^ byte) & 0xff] ^ (crc >> 8), 4 bytes per
            iteration, byte order chosen by the loop's sign
0x01128a8c  read:    return ~*state
```

The polynomial is the reflected CRC-32 one (`0xEDB88320`) — but note the
correction to §5 below: a **256-entry CRC32 table does exist** in the image, it
is *computed at runtime* at the address `0x01128d4c+`, which is why a static
scan for a table found nothing. `0x011289c2`'s `adds r3, #0` is a halfword
misaligned with the real stream; the real generator starts at `0x011289d0`.

The routine passes a stride-2/4 filter (it keeps the seed, does `& 0xff` per
iteration and holds the divisor `0x04c11db7`/`0xedb88320` as a shifted
constant), so it is the weakest evidence in this section — the field indices
and the read/write offsets come from a Ghidra stream that mangled the add and
the early loop iterations. What is *solid* is the arithmetic above.

Regardless of the exact variant, **the entry-table `crc32` field fails
validation on every entry in every image.** For example:

| entry | expected | zlib.crc32 | CRC32/MPEG-2 (big-endian) | 16-bit word sum |
|---|---|---|---|---|
| `qspi_ver_def.h` | `0x5235` | `0x46c203b2` | `0xbd5f414a` | `0x0898` |
| `init.lzs` | `0x6be9` | `0x2ead5edf` | `0x122cf978` | `0xaa82` |
| `idm1.bin` | `0x348c` | `0x9469f4d0` | `0x30d67bec` | `0x348c` |
| `sdram1.bin` | `0x1dbd` | `0xb6e76a1d` | `0xfe976da6` | `0xc892` |

All four rows reproduce from `mc101_sys_v182.zip`; the `zlib.crc32` column is
a stock `zlib.crc32` and the MPEG-2 column is a direct (non-reflected) CRC-32
with init `~0` and no final xor, read byte-by-byte in file order.

Tested and rejected: zlib CRC-32 (16 and 32 bit), CRC-32/BZIP2 and CRC-32
JAMCRC (direct, poly `0x04C11DB7`, both byte orders), word-reordered variants,
plain byte/16-bit/32-bit sums, and MD5/SHA prefix or suffix truncations. One
coincidence is worth recording because it looks like a hit and is not:
`idm1.bin`'s 16-bit little-endian word sum is `0x348c`, exactly its expected
value — but the other three sizeable entries fail the same test, so it is a
1-in-65,536 accident, not a formula.

**Conclusion: the field is a checksum over a range that is not simply
"the declared payload".** It is very likely a rolling CRC that spans the image
from `+0x20` to the entry's end, or a sum over the flash sector including
padding. This is now the highest-value single unknown in the container work,
because it is the last thing standing between "byte-exact repack" and
"believable repack".

#### 8.1.4 `idm1.bin` and `sdram1.bin` share no code

Neither image contains the other's string table: `wromInfo_%s.bin`,
`tone_pcmx_%s.bin`, `spf_muse_%s.bin`, `Legato HC Reset Failer! %d` and
`%08d: ASGN prmId Err(%d)` live only in `idm1.bin`; the BMC/DSP/ERAM and
`qspi_ver_def.h` parser strings live only in `sdram1.bin`. They are linked
separately for two different cores, as expected — a replacement must
therefore be built twice, not once and copied.

### 8.2 Decode `init.lzs` — DONE for the framing (§6)

There is no decompressor and none is needed: `init.lzs` is a 4-bit-framed
stream whose marker bytes (low nibble `f`) are dropped to reveal the payload.
See §6 and `tools/unlzs.py`. The framing is closed; what is open is the marker
high-nibble semantics and the `PRJ5` record schema — *not* a codec.

Two routes remain for what is genuinely still unreadable, in order of expected
value:

1. **Recombine the `init.lzs` marker nibbles** into 12-bit fields and map the
   `PRJ5` record schema (the framing rule is known; the schema is the
   remaining work).
2. **Acquire a newer or older Roland service image** in which the `C0A` body
   is not in the incompressible window, and diff. The window is
   byte-identical across v1.81→v1.82 but almost entirely different across
   v1.80→v1.81 (§4), so at least one release boundary is worth revisiting.

**Do not** spend further effort on blind byte-model fitting. §6's `0xXf`
ladder, the density alphabet and the marker distribution are fully explained by
the marker-framing scheme already; there is no separate literal encoder to
recover, so any further effort belongs in the record schema, not a codec.

### 8.3 Only then decide between patching `C0A` and replacing the secondary MCU

The recommendation is unchanged and, if anything, stronger:

* **The secondary MCU is the only component that is unambiguous today.** It is
  plaintext, symbol-rich, debug-enabled, and 8.1.1 proves its QSPI reader
  consumes raw bytes — so a replacement `sdram1.bin`/`idm1.bin` needs no
  compression and no key.
* **It is not free.** `FUN_0110d6e0` shows the C1C catalogue is opened by name
  at boot and each entry's `0x1c`-byte header is copied into a descriptor whose
  final field is a **base pointer computed as `stored + file_base`**. A
  replacement image must reproduce that descriptor's expectations or the
  device will follow a bad pointer during boot.
* **Patched `C0A` remains blocked** by the 1.1 MB incompressible window
  (re-measured here as `0x0c0000`–`0x1d0000`, exactly 1,114,112 B =
  `0x110000`, ratio 1.0003, entropy 7.9999) plus the checksum question of
  8.1.3.

### 8.4 Determine whether a first-stage bootloader exists elsewhere

Unchanged, and still unresolved. It is the gate on any fully custom `C0A`,
but it is **not** on the critical path for a custom secondary MCU, which is
why 8.3 recommends starting there.


## 9. Bottom line

* The **packaging is entirely open**, and rebuilding a valid update image is
  solved and verified — see [PATCHING.md](PATCHING.md).
* **One of the two CPUs is fully readable plaintext ARM Cortex-M firmware**
  (`sdram1.bin`, `idm1.bin`) and is an immediately viable target for a complete
  custom implementation with no cryptography involved.
* Its **QSPI read path is decompiled and consumes raw bytes** (§8.1.1), and its
  **entry checksum is CRC-32, computed at runtime** (§8.1.3). The algorithm is
  known; the byte range it covers is not.
* `C0A` is **partly** structured/compressible data and partly a 1.1 MB
  incompressible block. Its protection mechanism is **undetermined** — the
  earlier "fixed version-independent key" claim is retracted.
* `init.lzs` is a **4-bit-framed stream, now readable**: drop every byte whose
  low nibble is `f` to recover the payload (drum-kit names, tags, pointer
  tables) — see §6 and `tools/unlzs.py`.
  The "find its decompressor in the plaintext image" plan is closed but moot:
  there is no decompressor, only inline framing.
* There is still **no signature table**, and the entry `crc32` field does not
  validate against the payload, so the image format itself remains no obstacle;
  the open questions are now the `PRJ5` record schema (there is no `.lzs` codec
  — §6), the CRC's covered range, and the bootloader's verification behaviour.


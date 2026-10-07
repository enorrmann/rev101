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
+0x28   u32 LE   entry-base field    observed 0x20
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
0x2c   4 B   0x00000060            load offset
0x30   4 B   0x000c0040            load address
0x34  12 B   0xffffffff x3         erased region
0x40   4 B   0x000c0060            mirror
0x44   4 B   0x003565b0            payload size (see note)
0x50   4 B   digest
0x54   4 B   0xb6020001            flags / format id
0x5c   4 B   0xffffffff
```

*Size note:* for v1.82 the field is `0x3565b0` while filesize − 0x60 is
`0x3565f0`; the delta is a fixed 0xa0 tail. The tooling records the value and
asserts only that the delta is non-negative and < 0x1000, rather than
pretending to a byte-exact rule we have not proven.

### Region map of the C0A body

Measured by zlib ratio per 16 KiB block, over the 3,499,504-byte body:

| offset range | zlib ratio | entropy | interpretation |
|---|---|---|---|
| `0x00000`–`0xb6000` | 0.0 – 0.99 | mixed | **structured / compressible data** (real code+data) |
| `0xb6000`–`0x1d0000` | **1.0004** | **7.9999** | **incompressible ≈ 1.1 MB** |
| `0x1d0000`–`0x350000` | 0.00 – 0.99 | mixed | structured, large zero runs |

Whole-body zlib ratio is 0.733; the incompressible window alone is 1.0003.
This is why a whole-body entropy figure of 7.888 looked like "encryption" and
was misleading — the body is a **mixture**, dominated by compressible content.

### Version-to-version comparison

Body bytes identical (out of 3,499,504):

| pair | whole body | code region `0..0xb6000` | window `0xb6000..0x1d0000` |
|---|---|---|---|
| v1.80 → v1.81 | 24.69 % | 75.59 % | **0.39 %** |
| v1.81 → v1.82 | 94.02 % | 99.69 % | **100.00 %** |

Interpretation: the `0xb6000`–`0x1d0000` block is byte-identical across
v1.81→v1.82 (a small point release) but almost entirely different across
v1.80→v1.81 (a large feature release). Whatever that block is, it is **not**
a per-version re-keyed stream cipher, and it is equally not proven to be a
single stable ciphertext. It may be a large compressed/packed data blob whose
contents genuinely changed between 1.80 and 1.81.

**What is safe to say:** that window is high-entropy and incompressible.
**What is not safe to say:** that the firmware is protected by one
version-independent cipher key.

## 5. What is protected, and what is not

**Immediately usable, no cryptography:**
* Tar container, member names/layout/sizes/mtimes.
* QSPI container format, all entry tables, all `size`/`offset` fields.
* `sdram1.bin` + `idm1.bin` — complete plaintext ARM Cortex-M firmware.
* All of `C1C`'s 16 entries and `C0C`'s smaller metadata entries.
* `qspi_ver_def.h`, build dates, version strings, load addresses, digest field.

**Not yet readable:**
* `init.lzs` — the compressed application runtime (see §6).
* The 1.1 MB incompressible window inside `C0A`.
* Whether the outer container's digest is verified by a boot ROM (unknown —
  the bootloader for the very first stage is not in these four members).

### CRC fields do not validate

The `crc32` fields in the QSPI entry table did **not** match a computed
`zlib.crc32` over the extracted payload for any entry, in any version, in any
of the four images. The outer tar carries no signature table at all. Whatever
integrity mechanism exists lives inside the bootloader, not in the container.

## 6. `init.lzs` — compressed runtime (NOT yet decompressed)

`init.lzs` (969,045 B) holds the application runtime; it contains the
Python-style traceback strings visible in the parent image. Status:

**Established (with controls):**
* Entropy 6.73 bits/byte — structured, **not encrypted**.
* A shuffled control over the identical byte distribution yields 73 printable
  runs ≥8 chars; the real stream yields **3,702**. That ~50× excess is real
  structure, not a statistical accident.
* Byte histogram shows a flat ~29,700 bump on every `0xXf` value plus `0x2f`;
  the low nibble `0xf` appears 470,382 times (7.77× expected) while the high
  nibble is nearly flat. This is a **4-bit symbol stream** where `0xf` is the
  dominant token (27.2 % of 1,937,962 nibbles).
* Bit-level balance is 41.2 / 58.8 — a variable-length code, not uniform data.

**Ruled out** (attempted, no output > 64 KiB): zlib, raw deflate (all window
bits), gzip, bzip2, LZMA-alone, XZ, and LZ4 — each at every offset `0..0x300`
of the file, plus a broad magic scan. Simple 4-bit repacking in either nibble
order does not produce readable output either.

**Conclusion:** the codec is bespoke, consistent with the `.lzs` name. Blind
inference is exhausted; the next step needs the algorithm itself.

### How to obtain the `.lzs` algorithm
1. Locate a decompressor inside the **plaintext `sdram1.bin`** — the secondary
   MCU parses these names (`wromInfo_%s.bin`, `tone_pcmx_%s.bin`), so a
   matching routine likely exists there. This is the most promising route
   because it needs no key.
2. Find an open-source implementation for a Roland/KORG `.lzs` variant.

## 7. Verification

```
$ make test
18/18 checks passed      # tests/test_roundtrip.py
9/9 checks passed        # tests/test_full_rebuild.py
```

The acceptance test is **byte-exact full-container rebuild** for all three
releases (20,285,440 B each). A byte-exact rebuild when nothing is modified
means any difference in a later modified image is provably the intended change.

## 8. Recommended next steps, in order

1. **Reverse `sdram1.bin` properly** (Ghidra, ARM/Thumb, base `0x01000000`) —
   find the QSPI parser, the flash routines, and any `.lzs` decompressor. No
   key required; highest expected value.
2. **Decompress `init.lzs`** once the algorithm is known → yields the updater
   runtime and very likely the routines that consume `C0A`.
3. **Only then** decide between patching `C0A` and replacing the secondary MCU
   firmware outright.
4. Determine whether a first-stage bootloader exists elsewhere (internal ROM
   or separate flash). Until that is known, the trust model for a fully custom
   `C0A` remains unproven.

## 9. Bottom line

* The **packaging is entirely open**, and rebuilding a valid update image is
  solved and verified — see [PATCHING.md](PATCHING.md).
* **One of the two CPUs is fully readable plaintext ARM Cortex-M firmware**
  (`sdram1.bin`, `idm1.bin`) and is an immediately viable target for a complete
  custom implementation with no cryptography involved.
* `C0A` is **partly** structured/compressible data and partly a 1.1 MB
  incompressible block. Its protection mechanism is **undetermined** — the
  earlier "fixed version-independent key" claim is retracted.
* `init.lzs` is compressed with a bespoke codec and is the key to the runtime.
* There is **no CRC or signature table in the container**, so the image format
  itself is no obstacle; the open questions are the `.lzs` codec and the
  bootloader's verification behaviour.

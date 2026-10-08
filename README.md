# rev101 — Roland MC-101 (RPG69) firmware reverse engineering

Working notes and tooling from reverse-engineering three MC-101 firmware
releases, with the goal of building custom firmware.

## What this is

The three `mc101_sys_v18*.zip` files are official Roland updates. Each contains
a plain POSIX tar (`MC101_UPA_up.bin`) holding four raw flash images for two
CPUs. Analysis of what lives where, and what is protected, is in
[docs/FINDINGS.md](docs/FINDINGS.md).

## Quick start

```sh
make help          # list targets
make test          # verification suite (56 checks)
make inspect       # print container structure for all three versions
make extract-all   # unpack everything into firmware/raw/
make candidate     # build a demo modified image into build/
make ghidra        # analyse the plaintext secondary-MCU firmware
```

## Layout

```
docs/FINDINGS.md        container formats, region map, what is/isn't protected
docs/PATCHING.md        how to build and verify a modified image
docs/USAGES.md          what you can do right now, with worked custom-firmware examples
docs/SECONDARY_MCU.md   the plaintext ARM Cortex-M firmware (Ghidra results)

tools/mc101fw.py        tar + QSPI parse/rebuild library (stdlib only)
tools/rb_record.py      parse the confirmed plaintext record-container schema
tools/unlzs.py          unframe the 4-bit-marked `init.lzs` stream (payload readable, PRJ5 field schema still open)
tools/extract.py        extract members and QSPI entries
tools/patch.py          replace QSPI entry payloads and repack
tools/make_candidate.py build a demo modified image
tools/ghidra_analyze.sh headless Ghidra analysis driver
tools/ghidra_decompile.sh decompile one function, or every function (--all)
tools/ghidra/*.java     Ghidra post-scripts (function dump, decompile, string xrefs)

tests/                  round-trip, full-rebuild and patch verification
firmware/               generated extraction output (gitignored)
build/                  generated candidate images (gitignored)
```

## The key result

**Full-container rebuild is byte-exact for all three releases.** Verified:

```
$ make test
18/18 checks passed      tests/test_roundtrip.py
9/9  checks passed       tests/test_full_rebuild.py
9/9  checks passed       tests/test_patch.py
14/14 checks passed      tests/test_safety.py
2/2  checks passed       tests/test_unlzs.py
4/4  checks passed       tests/test_rb_record.py
```

Because a rebuild of unmodified input reproduces the original byte-for-byte,
any difference in a modified image is provably the change you intended — no
collateral drift in tar headers, entry tables, alignment padding or unrelated
members.

## Handling untrusted images

QSPI entry names and tar member sizes come straight from the image file. If you
point this tooling at an image you did not build yourself:

* entry names are reduced to a safe basename and the final write path is
  re-checked against the output directory (`safe_entry_name`,
  `resolve_within`), so a crafted entry named `../../x` cannot escape;
* declared member sizes are bounded (`MAX_CONTAINER_BYTES`,
  `MAX_MEMBER_BYTES`) to prevent decompression-bomb-style memory exhaustion.

`tests/test_safety.py` exercises both.

## Current status of the custom-firmware goal

| component | status |
|---|---|
| tar + QSPI container formats | **solved**, byte-exact repack, confirmed by the device's own parser |
| `sdram1.bin` / `idm1.bin` (secondary MCU) | **plaintext ARM Cortex-M**, QSPI read path decompiled; primary target now |
| `C1C` entries, `C0C` metadata | plaintext, editable in place |
| QSPI entry `crc32` field | algorithm is **CRC-32** (confirmed), the covered byte range is **not** — see [docs/SECONDARY_MCU.md](docs/SECONDARY_MCU.md) |
| `C0A` main application | partly compressed, ~1.1 MB incompressible window (`0x0c0000`–`0x1d0000`) of undetermined protection |
| `init.lzs` runtime | **PRJ5 project, not yet fully decoded**: `[data][0xXf]` 12-bit framing confirmed, names readable via `tools/unlzs.py`; field-level record schema unresolved — see [docs/FINDINGS.md](docs/FINDINGS.md) §6 |
| bootloader verification | unknown — first stage not present in these images |

The realistic custom-firmware target today is the **secondary MCU**, which
requires no cryptography: the QSPI loader there reads entry payloads verbatim,
so a replacement must be a raw image. See
[docs/SECONDARY_MCU.md](docs/SECONDARY_MCU.md) and §8 of
[docs/FINDINGS.md](docs/FINDINGS.md) for how that was established.

## Hardware warning

Nothing in this repository writes to hardware. `make candidate` produces an
image file and reports its diff against the base; flashing it is your decision.

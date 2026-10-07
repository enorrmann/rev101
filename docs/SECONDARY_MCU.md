# MC-101 secondary-MCU firmware (`sdram1.bin` / `idm1.bin`)

Both files are **plaintext ARM Cortex-M code**, extracted from the `C1A` QSPI
member. No key or decompressor is required — this is the one CPU in the product
whose firmware can be read, studied and **replaced outright today**.

## Target identification

| property | value | evidence |
|---|---|---|
| architecture | ARM Cortex-M, Thumb | Capstone decodes clean code; `revsh r0,r0; bx lr`, `movw/movt/bx` idioms |
| family | **STM32H7** | peripheral literals `0x30000000` (D2 SRAM, 1909×), `0x24000000` (AXI SRAM, 106×), `0x38000000` (D3 SRAM, 13×), `0x10000000` (ITCM, 138×), `0x08000000` (flash), `DBGMCU` at `0xE0042000` |
| dual-core capable | yes | `CORE1_LOAD_QSPI`, `CORE1_BMCSetup`, `CORE1_DSPEnable`, `Core1Total`, `Check CORE0 Exists = %s` |
| custom silicon | **Roland BMC** | symbol `RolandVDN_BMC`; peripherals `BMCInitDAC`, `BMCInitERAM`, `BMCInitUDL`, `BMCInitWaveBus`, `Bmc_init_DSP`, `CBmcDspDrv`, `CBmcDspMgr` |

### Load addresses

`idm1.bin` loads at **`0x01100000`** and carries the reset vector table at
`+0x20`:

```
+0x20  0x200a91c8   initial SP   (SRAM, 0x200a91c8)
+0x24  0x01100de5   Reset       (Thumb-bit set -> 0x01100de4)
+0x28  0x01100e55
+0x2c  0x01100e57
+0x30  0x01100e59
+0x34  0x01100e5b
+0x38  0x01100e5d
```

Decoding the reset handler at `0x01100de4` gives coherent init code:
```
orr r1, r1, #0x300
orr r1, r1, #0x1fa0000
orr r1, r1, #0x4000000
str r1, [r0]
bl  0x1101a3a
wfi
b   0x1100df6        ; park forever
```

`sdram1.bin` is the larger payload and is imported at `0x01000000`.

A scan of `idm1.bin` for Cortex-M vector tables found exactly **one** valid
table (`+0x20`); the other 29 candidate sites had no plausible handler chains.
So `idm1.bin` = boot stub + vector table, `sdram1.bin` = the bulk application.

## This is a debug/test build with a full diagnostic shell

The image ships with an extensive self-test and dump facility, and a
**symbol table with 624 C++ mangled names**. Notable recovered symbols:

```
13CQSPIFileRead          15CEZUtilVExpQSPI       CORE1_LOAD_QSPI
16CEZUtilQSPIBlock       15CEZUtilQSPIDump       RHY_LOAD_QSPI
QSPIBlock                QSPICSum                QSPIDump
SN_INST_LOAD             INST_LOAD               SAVE_LOAD
BMCHardwareCheck         BMCInitERAM             BMCInitWaveBus
CFspDspTest::TestEram()  CFspDspMgr              CChoSDD320
```

Debug output strings (all live in the image):

```
%08d: QSPI%d Test CRC32 Start...
%08d: QSPI%d Test Size Error !
%08d: QSPI%d Test End  (Erapsed Time = %d)
%08d: VQSPI Clear Start...
QSPICSum = %04X
Exists %d Blocks on QSPI%d
QSPI Test File '%s'
```

There is a full test menu with an area/checksum table:

```
Area     Adrs     Size     Sum      Calc     Test
-------- -------- -------- -------- -------- ----
```

and named flash regions:
```
ERAM    QSPI App   QSPI Dat   WAVE 000   WAVE 001   ----   Clear
```

plus `Eram Test OK / NG / Busy`, `DSP Test Started (DSP Stopped)`, and
`Sample Info CSum = %08Xh`.

A version banner format string is also present — useful for identifying what
the code expects to read back:
```
Version     | %d.%02d
Build #     | %04d
Build Date  | %s
Comment     | %s
Max Voice   | %3d
Total Voice | %3d
CORE%1d (%s/WROMx%d, FS=%s)
    BMC #%d(%s)
```

## `qspi_ver_def.h` parser (cross-validates our container work)

The secondary MCU parses the same `qspi_ver_def.h` file we extract from
`C0C`/`C1C`. Its key table sits at file offset `0x2c8ad0` and lists exactly the
field names our parser expects:

```
QSPI_DATA
PCMEX_WAVE
PCMX_WAVE
PRM_VER
TARGET
PCM-EX
```

and values `0.13`, `0.058`, `0.09`, `0.039` — matching the real file's
`T(PRM_VER, 0.039)` and `T(QSPI_DATA, 0.058)`. It also emits diagnostics like
`'QSPI_DATA' is not found at QSPI Info Ver`, i.e. it looks up keys by name.

This independently confirms the container parsing in `tools/mc101fw.py`.

## Ghidra results

Headless analysis (Ghidra 11.3.2, `ARM:LE:32:Cortex`):

| image | base | functions recovered |
|---|---|---|
| `idm1.bin` | `0x01100000` | **1,062** |
| `sdram1.bin` | `0x01000000` | **2,069** |

Whole-program decompilation for offline grepping is available as a Ghidra
post-script (`tools/ghidra/DecompAll.java`, driven by
`tools/ghidra_decompile.sh --all <image>` or `make decompile`), which writes
`$GHIDRA_WORK/<image>.decompall.txt`. Most of the "Checksum algorithm" and
"Read path" sections below were derived from that file rather than from
targeted `DecompOne` calls, because those routines have no direct callers in
the analyser's call graph.

Largest recovered functions:

`idm1.bin`

| address | size |
|---|---|
| `0x01106204` | 5464 |
| `0x01116070` | 4306 |
| `0x01111ce4` | 3460 |
| `0x0110f542` | 2168 |
| `0x01107816` | 1880 |

`sdram1.bin`

| address | size |
|---|---|
| `0x01021afe` | 6428 |
| `0x01032d00` | 5046 |
| `0x0101caec` | 2918 |
| `0x01025ffe` | 2758 |
| `0x0107b302` | 2682 |

### The `qspi_ver_def.h` parser, decompiled

Xref analysis on the key strings pinpoints the parser at **`0x01075972`**
(400 bytes). It decompiles to clean, readable C:

```c
void FUN_01075972(undefined4 *param_1)
{
  *param_1 = 0; param_1[1] = 0; param_1[9] = 0;
  ...
  FUN_010758fe(param_1);
  FUN_010756ea(param_1);
  iVar5 = _DAT_01075758;                       // table of {name, value} pairs
  iVar6 = 0;
  // look up "aPCMEX_WAVE" by name
  while (iVar2 = thunk_FUN_01129c74(*(undefined4 *)(iVar5 + iVar6*8),
                                    s__aPCMEX_WAVE_0107575a + 2), iVar2 != 0) {
    iVar6++;
    if (4 < iVar6) goto LAB_010753ac;
  }
  thunk_FUN_01129948(local_30, *(undefined4 *)(iVar5 + iVar6*8 + 4));
  ...
LAB_010753ac:
  if (4 < iVar6)
    thunk_FUN_011023e4(s__PCMEX_WAVE__is_not_found_at__qs_01075768);
  // ... same pattern for "PCMX_WAVE" and "QSPI_DATA"
  iVar6 = thunk_FUN_011241a6(s_QSPI_DATA_010757d4);
  if (iVar6 < 0)
    thunk_FUN_011023e4(s__QSPI_DATA__is_not_found_at_QSPI_010757e0);
  ...
}
```

This confirms the file is a **name→value key table** exactly as our extractor
treats it, and confirms the error strings we saw in the string dump
(`'PCMEX_WAVE' is not found at 'qspi_ver_def.h'`) are live code paths.

Associated functions in the same module (`0x01075700`–`0x01076200`):
`FUN_010758fe` (98 B), `FUN_010756ea` (276 B), `FUN_01075a34` (82 B),
`FUN_01075b4c` (208 B), `FUN_01075c1c` (364 B), `FUN_01075d98` (202 B).

### Checksum algorithm: CRC-32, over an unknown byte range

Attempts to pin the integrity algorithm:

* **A 256-entry CRC-32 table exists but is *computed at runtime*.** Ghidra's
  function list misses the generator because it sits between two
  mis-analysed functions; disassembling `idm1.bin` at `0x011289d0` recovers it:

  ```
  011289d8  ldr  r4, [pc, #0xbc]          ; r4 = 0xEDB88320  (literal @0x1128a98)
  011289da  ldr  r6, [pc, #0xc0]          ; r6 = 0x200a722c  (literal @0x1128a9c)
  011289dc  mov  ip, #0                   ; i = 0
  011289e0  mov  r1, ip                   ; crc = i
  011289e2  movs r3, #4
  011289e4  tst  r1, #1                   ; 8 iterations, unrolled x4
  011289ea  eorne r2, r4, r1, lsr #1      ; lsr on crc, eor poly if bit0 clear
  011289ee  lsreq r2, r1, #1
  ...
  01128a00  str  r1, [r6, ip, lsl #2]     ; table[i] = crc
  01128a0e  strb r1, [r5]                 ; "table initialised" latch
  ```

  So the reflected CRC-32 polynomial is an immediate after all (`0xEDB88320`),
  and the 256-entry table is written to **RAM at `0x200a722c`**. The update
  routine follows at `0x01128a1e`, loading that same pointer:

  ```
  crc = table[(crc ^ byte) & 0xff] ^ (crc >> 8)    ; 4 bytes per iteration
  0x01128a8c:  return ~*state
  ```

  This is why a static scan of the *file* for a materialised table found
  nothing — **the earlier "no CRC32 table exists" conclusion is retracted.**

* Caveat: the stream at `0x011289c2` is not clean Thumb — `adds r3, #0` is a
  halfword misaligned with the real code — and the early iterations of the
  update routine are mangled by the analyser. The arithmetic above is solid;
  the exact register/offset plumbing is not.

* **The stored `crc32` field still does not validate.** No candidate reproduces
  it for any entry in any image. Tested and rejected:

  | candidate | `qspi_ver_def.h` (expect `0x5235`) | `init.lzs` (expect `0x6be9`) |
  |---|---|---|
  | `zlib.crc32` (reflected, bitwise) | `0x46c203b2` | `0x2ead5edf` |
  | CRC-32/MPEG-2, big-endian, init `~0` | `0xbd5f414a` | `0x122cf978` |
  | same, final xor `~0` | `0x42a0beb5` | `0xedd30687` |
  | 16-bit LE word sum | `0x0898` | `0xaa82` |
  | byte XOR | `0x33` | `0xae` |

  > These two rows were recomputed against the images in this repository: the
  > `%` figures and the candidate values above all reproduce from
  > `mc101_sys_v182.zip` with a stock `zlib.crc32` and a 20-line CRC helper.

  `idm1.bin`'s 16-bit LE word sum happens to equal its expected `0x348c`, but
  the other sizeable entries fail the same test, so that is a 1-in-65,536
  coincidence. See [FINDINGS.md](FINDINGS.md) §8.1.3 for the full table.

**Therefore** the field is a CRC-32 over a range that is not simply "the
declared payload" — most likely a rolling CRC that starts at the image header
(`+0x20`) and covers the entry's sector including alignment padding. Finding
that range is the highest-value remaining task in the container work. It is
*not* a blocker for a secondary-MCU replacement, since the entry table is
carried through verbatim by `build_qspi`.

## Read path: the QSPI loader never decompresses

This is the most useful decompilation result for the custom-firmware goal, and
it comes from `idm1.bin` `FUN_0110d6e0` (C1C catalogue loader),
`FUN_01123bf0` (name→entry lookup) and `FUN_0112444e` (raw read primitive).
See [FINDINGS.md](FINDINGS.md) §8.1.1 for the listings.

* `FUN_0112444e(buf, offset, len)` copies `len` bytes from the QSPI window
  straight into `buf`. Word-wise bulk, byte-wise tail. No transform.
* Every entry payload is therefore **exactly its stored bytes**, bounded by a
  `0x1000000` (16 MiB) aperture mask.
* The name comparison is 16 bytes, case-insensitive, with non-printables folded
  to `_`, which explains the truncated on-image names (`tone_pcmx_cmn.bi`,
  `inst_pcmx_rpg68.`).

**Consequence for a replacement image:** `sdram1.bin` / `idm1.bin` must be
raw, uncompressed images. Do not compress them.

Also in that loader, each entry's `0x1c`-byte header is copied into a
descriptor whose last field is a **base pointer computed as `stored + file_base`**.
A replacement image must satisfy that expectation or the device will follow a
bad pointer at boot.

## Why `init.lzs` cannot be solved from these images

A whole-file search for `init.lzs`, `.lzs` and `lzs` over `C0A`, `C0C`, `C1A`,
`C1C`, `sdram1.bin` and `idm1.bin` returns **one** hit: the filename in `C0C`'s
entry table. `VQSPI` occurs exactly twice in the whole extraction, both in
`sdram1.bin`.

Combined with the read path above, this means the decompressor is **not**
reachable from the QSPI loader in either plaintext image. It lives either in
the unreadable `C0A` main-CPU application or behind a pointer table the
analyser did not resolve. The "find the `.lzs` routine in `sdram1.bin`" plan is
therefore **closed**; the algorithm must come from an external implementation.

Related false lead, recorded so it is not re-explored: `sdram1.bin`
`FUN_01075c1c` / `FUN_01075b4c` contain what look like shift amounts
(`>> 7`, `>> 11`, `>> 3`, `>> 5`) cycling over a buffer. They are **not** a
bit-reader — `0x6171` is a BMC command tag and the third byte is a register
field index, which is why the apparent widths trail off into noise. The strings
in that module (`QSPICSum = %04X`) come from `FUN_01075d98`, the CRC-32
self-test, which uses the algorithm above.

## Next steps

1. **Determine the CRC-32 byte range** the entry `crc32` field covers, by
   re-running the recovered algorithm over candidate ranges until it reproduces
   a stored value for several entries at once.
2. **Reconcile the entry-base arithmetic** in `FUN_01123bf0`: it stores the
   `+0x28` field (`0x10`) and indexes `base + i*0x20`, which does not match the
   observed `0x30` table start. Either the field means something else or the
   decompilation elides an add.
3. **Build the secondary-MCU replacement interface map** from the recovered
   symbols (`CORE1_LOAD_QSPI`, `BMCInit*`, `CEZUtilQSPI*`, `CChoSDD320`) so a
   custom image can be linked against the real entry points.
4. Locate `13CQSPIFileRead` and `15CEZUtilQSPIBlock` (mangled-name string table
   at image offset `0x2be1ec`) and decompile them to close out the container
   read path.

To reproduce the analysis:

```sh
export XDG_CONFIG_HOME=/tmp/rev101/ghidra_home
/home/emilio/ghidras/ghidra_11.3.2_PUBLIC/support/analyzeHeadless \
  /tmp/rev101/ghidra_proj mc101 \
  -import sdram1.bin \
  -processor ARM:LE:32:Cortex \
  -loader BinaryLoader -loader-baseAddr 0x01000000 \
  -postscript DumpInfo.java
```

(`~/.config` is read-only here, hence the `XDG_CONFIG_HOME` override.)

## Why this matters for the custom-firmware goal

* This image is **plaintext, symbol-rich and debug-enabled** — by far the best
  documented part of the product.
* The `qspi_ver_def.h` parser is located (`0x2c8ad0` key table) and the QSPI
  read path is decompiled. The `.lzs` decompressor is **not** here — see
  "Why `init.lzs` cannot be solved from these images" above.
* The BMC/DSP/ERAM/QSPI driver split is now named, so a replacement firmware
  has a clear interface map to work against.
* Because the QSPI loader consumes raw bytes and never transforms them, a
  replacement `sdram1.bin` / `idm1.bin` is the one custom-firmware target that
  needs neither a key nor a codec.


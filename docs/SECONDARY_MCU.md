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
| `idm1.bin` | `0x01100000` | **1,172** |
| `sdram1.bin` | `0x01000000` | **2,069** |

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

### Checksum algorithm: not yet identified

Attempts to pin the integrity algorithm:

* **No 256-entry CRC32 table** exists anywhere in the image — a scan for a
  reflected-style table (`table[0]==0`, `table[i] & 0xff == i` for all i)
  found zero candidates.
* The constants `0xEDB88320`, `0x04C11DB7`, `0xA001` do not appear as
  immediates.
* `0x1021` (CRC-16/CCITT) appears twice (`0x0b53fb`, `0x0b5457`) but neither
  site disassembles coherently, so those are data, not confirmed code.
* The `%08d: QSPI%d Test CRC32 Start...` and `QSPICSum = %04X` strings sit
  between Ghidra functions with **no direct xrefs**, i.e. they are reached
  through computed addresses — consistent with a debug menu dispatch table.

So the algorithm the device validates remains open. It is almost certainly
reachable from the debug menu dispatch, which is where to look next.

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
* The `.lzs` decompressor and the `qspi_ver_def.h` parser both plausibly live
  here. The parser is already located (`0x2c8ad0` key table). Finding the
  `.lzs` routine here is the highest-value remaining task and needs no key.
* The BMC/DSP/ERAM/QSPI driver split is now named, so a replacement firmware
  has a clear interface map to work against.

## Next steps

1. Locate the `.lzs` decompressor in `sdram1.bin` (search for the routine that
   consumes `init.lzs`, or for LZSS-style bit-reader code).
2. Decompile `13CQSPIFileRead` and `15CEZUtilQSPIBlock` to confirm the QSPI
   container read path end to end.
3. Use the `QSPI%d Test CRC32` routine to determine the checksum algorithm the
   device actually validates — this is the integrity question left open in
   [FINDINGS.md](FINDINGS.md).

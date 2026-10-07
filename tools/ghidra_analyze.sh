#!/usr/bin/env bash
#
# Headless Ghidra analysis of the MC-101 secondary-MCU firmware.
#
# Recovers functions and symbols from the plaintext ARM Cortex-M images that
# ship inside the C1A QSPI member:
#
#   idm1.bin    -> loads at 0x01100000  (boot stub + reset vector table)
#   sdram1.bin  -> loads at 0x01000000  (bulk application)
#
# The load addresses come from the reset vector table at idm1.bin+0x20, whose
# handler addresses (0x01100de5 ...) reveal idm1's base, and from the peripheral
# literals (0x30000000 D2 SRAM, 0x24000000 AXI SRAM) which identify STM32H7.
#
# Usage:
#   tools/ghidra_analyze.sh                 # both images
#   tools/ghidra_analyze.sh sdram1.bin      # one image
#
# Writes <image>.ghidra.txt containing "FUNC <address> <name> size=<n>" lines.
#
# NOTE: Ghidra will not start when $HOME/.config is not writable, so config and
# cache are redirected into GHIDRA_WORK (default /tmp/rev101).

set -euo pipefail

GHIDRA="${GHIDRA:-/home/emilio/ghidras/ghidra_11.3.2_PUBLIC}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${GHIDRA_WORK:-/tmp/rev101}"
PROJ="$WORK/ghidra_proj"

export XDG_CONFIG_HOME="$WORK/ghidra_home"
export XDG_CACHE_HOME="$WORK/ghidra_home"
export HOME="$WORK/ghidra_home"

mkdir -p "$WORK" "$PROJ" "$XDG_CONFIG_HOME"

if [[ ! -x "$GHIDRA/support/analyzeHeadless" ]]; then
  echo "error: analyzeHeadless not found at $GHIDRA/support/" >&2
  echo "       set GHIDRA=/path/to/ghidra_install" >&2
  exit 1
fi

find_img() {
  find "$REPO/firmware/raw" -name "$1" -print -quit 2>/dev/null || true
}

run_one() {
  local img="$1" base="$2" name
  name="$(basename "$img")"

  # Re-importing over an existing program fails, so analyse in place if the
  # image was already imported (use -process), otherwise import it.
  if [[ -d "$PROJ/mc101.rep" ]] && grep -qsx "$name" "$WORK/imported.txt" 2>/dev/null; then
      echo "=== re-analysing $name (already imported) ==="
      "$GHIDRA/support/analyzeHeadless" "$PROJ" mc101 \
        -process "$name" \
        -scriptPath "$REPO/tools/ghidra" \
        -postscript DumpInfo.java \
        -analysisTimeoutPerFile 2700 2>&1 \
        | grep -E "FUNCCOUNT|WROTE|ERROR|Analysis succeeded" || true
      return
  fi

  echo "=== analyzing $name at base $base ==="
  "$GHIDRA/support/analyzeHeadless" "$PROJ" mc101 \
    -import "$img" \
    -processor ARM:LE:32:Cortex \
    -loader BinaryLoader -loader-baseAddr "$base" \
    -scriptPath "$REPO/tools/ghidra" \
    -postscript DumpInfo.java \
    -analysisTimeoutPerFile 2700 2>&1 \
    | grep -E "FUNCCOUNT|WROTE|ERROR|Analysis succeeded" || true
  echo "$name" >> "$WORK/imported.txt"
}

IDM1="$(find_img idm1.bin)"
SDRAM1="$(find_img sdram1.bin)"

if [[ -z "$IDM1" || -z "$SDRAM1" ]]; then
  echo "error: idm1.bin / sdram1.bin not found under firmware/raw." >&2
  echo "       run 'make extract-all' first." >&2
  exit 1
fi

case "${1:-all}" in
  idm1.bin|idm1)     run_one "$IDM1" 0x01100000 ;;
  sdram1.bin|sdram1) run_one "$SDRAM1" 0x01000000 ;;
  all)               run_one "$IDM1" 0x01100000; run_one "$SDRAM1" 0x01000000 ;;
  *) echo "usage: $0 [all|idm1.bin|sdram1.bin]" >&2; exit 2 ;;
esac

echo
echo "function lists:"
ls -la "$WORK"/*.ghidra.txt 2>/dev/null || echo "  (none)"

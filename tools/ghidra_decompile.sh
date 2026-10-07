#!/usr/bin/env bash
#
# Decompile functions from an already-analyzed image.
#
# Prerequisite: run tools/ghidra_analyze.sh first so the project exists.
#
# Usage:
#   tools/ghidra_decompile.sh sdram1.bin 0x01075972 [more addresses...]
#   tools/ghidra_decompile.sh --all sdram1.bin
#
# Output:
#   specific addresses -> $GHIDRA_WORK/<image>.decomp.txt
#   --all              -> $GHIDRA_WORK/<image>.decompall.txt
#
# --all decompiles every recovered function into one greppable file
# (<address> <name> size=<n> headers).  Most of the routines documented in
# docs/SECONDARY_MCU.md were found that way, because they have no direct
# callers in the analyser's call graph.

set -euo pipefail

GHIDRA="${GHIDRA:-/home/emilio/ghidras/ghidra_11.3.2_PUBLIC}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${GHIDRA_WORK:-/tmp/rev101}"
PROJ="$WORK/ghidra_proj"

export XDG_CONFIG_HOME="$WORK/ghidra_home"
export XDG_CACHE_HOME="$WORK/ghidra_home"
export HOME="$WORK/ghidra_home"

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <image-name> <address> [address...]" >&2
  echo "       $0 --all <image-name>" >&2
  echo "  e.g. $0 sdram1.bin 0x01075972" >&2
  echo "  e.g. $0 --all idm1.bin" >&2
  exit 2
fi

if [[ "$1" == "--all" ]]; then
  IMG="$2"
  "$GHIDRA/support/analyzeHeadless" "$PROJ" mc101 \
    -process "$IMG" -noanalysis \
    -scriptPath "$REPO/tools/ghidra" \
    -postscript DecompAll.java 2>&1 \
    | grep -E "WROTE|ERROR|FAILED" || true
  echo
  echo "output: $WORK/$IMG.decompall.txt"
  exit 0
fi

IMG="$1"; shift

"$GHIDRA/support/analyzeHeadless" "$PROJ" mc101 \
  -process "$IMG" -noanalysis \
  -scriptPath "$REPO/tools/ghidra" \
  -postscript DecompOne.java "$@" 2>&1 \
  | grep -E "WROTE|ERROR|FAILED" || true

echo
echo "output: $WORK/decomp_out.txt"

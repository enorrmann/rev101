PY ?= python3

.PHONY: help test extract extract-all clean inspect candidate anchors crc-scan ciphers

help:
	@echo "MC-101 (RPG69) firmware reverse-engineering workspace"
	@echo ""
	@echo "  make test         run the full verification suite"
	@echo "  make extract      extract v1.82 members into firmware/raw/"
	@echo "  make extract-all  extract v1.80, v1.81 and v1.82"
	@echo "  make inspect      print container structure for all versions"
	@echo "  make candidate    build build/MC101_UPA_up.bin with a demo edit"
	@echo "  make ghidra       analyse the plaintext secondary-MCU firmware"
	@echo "  make decompile    decompile every function of both images"
	@echo "  make anchors      build the C0A ECB-anchor corpus (docs/C0A_EXPLOITATION.md §1)"
	@echo "  make crc-scan     search the QSPI entry crc32 range (§3)"
	@echo "  make ciphers      test 64-bit block ciphers against the corpus (§2)"
	@echo "  make clean        remove generated extraction output"
	@echo ""
	@echo "docs/FINDINGS.md      what the firmware is and what is protected"
	@echo "docs/PATCHING.md      how to build a modified image"

test:
	$(PY) tests/test_roundtrip.py
	@echo
	$(PY) tests/test_full_rebuild.py
	@echo
	$(PY) tests/test_patch.py
	@echo
	$(PY) tests/test_safety.py
	@echo
	$(PY) tests/test_unlzs.py
	@echo
	$(PY) tests/test_rb_record.py

extract:
	$(PY) tools/extract.py --version 182 --repack-check

extract-all:
	$(PY) tools/extract.py --all --repack-check

inspect:
	@for v in 180 181 182; do $(PY) tools/mc101fw.py mc101_sys_v$$v.zip; done

# Build a candidate image with one clearly-labelled, same-size edit, so you can
# verify the patch mechanism end to end.  This does NOT flash anything.
candidate: extract
	$(PY) tools/make_candidate.py

# Analyse the plaintext secondary-MCU firmware with Ghidra (requires a Ghidra
# install; set GHIDRA=/path if it is not at the default location).
ghidra: extract
	tools/ghidra_analyze.sh all

# Decompile every recovered function of both images into
# $GHIDRA_WORK/<image>.decompall.txt for offline grepping (requires `make
# ghidra` first to have created the analysis project).
decompile:
	tools/ghidra_decompile.sh --all idm1.bin
	tools/ghidra_decompile.sh --all sdram1.bin
	@echo "output: $${GHIDRA_WORK:-/tmp/rev101}/*.decompall.txt"

# C0A cryptanalysis helpers (docs/C0A_EXPLOITATION.md).  All are offline and
# read only the extracted images; `make extract-all` first.
anchors:
	$(PY) tools/find_anchors.py --diff 180 181
	$(PY) tools/find_anchors.py --diff 181 182

crc-scan:
	$(PY) tools/find_crc_range.py
	$(PY) tools/sweep_crc_range.py

ciphers:
	$(PY) tools/try_block_ciphers.py

clean:
	rm -rf firmware/raw firmware/decoded build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

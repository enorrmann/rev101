PY ?= python3

.PHONY: help test extract extract-all clean inspect

help:
	@echo "MC-101 (RPG69) firmware reverse-engineering workspace"
	@echo ""
	@echo "  make test         run the full verification suite"
	@echo "  make extract      extract v1.82 members into firmware/raw/"
	@echo "  make extract-all  extract v1.80, v1.81 and v1.82"
	@echo "  make inspect      print container structure for all versions"
	@echo "  make candidate    build build/MC101_UPA_up.bin with a demo edit"
	@echo "  make ghidra       analyse the plaintext secondary-MCU firmware"
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

clean:
	rm -rf firmware/raw firmware/decoded build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

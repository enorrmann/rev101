#!/usr/bin/env python3
"""Test the patch tool: a modification must change ONLY the intended bytes.

Acceptance criterion: patching one QSPI entry payload produces an image whose
diff against the base is exactly the bytes we changed -- no collateral drift in
the tar headers, entry tables, alignment padding or the other three members.

Run:  python3 tests/test_patch.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def main() -> int:
    failures = 0
    checks = 0

    base = REPO / "mc101_sys_v182.zip"
    if not base.exists():
        print(f"SKIP: {base.name} not found")
        return 0

    original = fw.load_container(base)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # 1. build a same-size modification of a plaintext C1C entry
        members = fw.parse_tar(original)
        c1c = next(m for m in members if "C1C" in m.name)
        img = fw.parse_qspi(c1c.data)
        target = next(e for e in img.entries if e.name.strip() == "qspi_ver_def.h")

        patched_payload = target.data.replace(b"0.039", b"9.999", 1)
        checks += 1
        if len(patched_payload) != len(target.data):
            failures += 1
            print("FAIL  test setup: replacement changed payload length")
            return 1
        if patched_payload == target.data:
            failures += 1
            print("FAIL  test setup: pattern '0.039' not found in target entry")
            return 1
        print("PASS  test setup: same-size in-place edit prepared")

        mod_file = tmp / "qspi_ver_def.h"
        mod_file.write_bytes(patched_payload)

        out_image = tmp / "MC101_UPA_up.bin"
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO / "tools" / "patch.py"),
                "--base", str(base),
                "--out", str(out_image),
                "--replace", f"RPG69_C1C_up.bin:qspi_ver_def.h:{mod_file}",
            ],
            capture_output=True,
            text=True,
        )
        checks += 1
        if proc.returncode != 0:
            failures += 1
            print(f"FAIL  patch.py exited {proc.returncode}\n{proc.stdout}\n{proc.stderr}")
            return 1
        print("PASS  patch.py completed")

        patched = out_image.read_bytes()

        # 2. length must be unchanged for a same-size edit
        checks += 1
        if len(patched) != len(original):
            failures += 1
            print(f"FAIL  length changed: {len(original):,} -> {len(patched):,}")
        else:
            print(f"PASS  container length unchanged ({len(patched):,} B)")

        # 3. the diff must be EXACTLY the 3 edited characters
        diffs = [i for i in range(len(original)) if patched[i] != original[i]]
        expected = 3
        checks += 1
        if len(diffs) != expected:
            failures += 1
            print(f"FAIL  expected {expected} changed bytes, got {len(diffs)}")
            for i in diffs[:10]:
                print(f"        {i:#x}: {original[i]:#04x} -> {patched[i]:#04x}")
        else:
            print(f"PASS  exactly {len(diffs)} bytes changed")

        # 4. the changed bytes must be inside the target entry's payload range
        c1c_off_in_tar = c1c.offset
        payload_lo = c1c_off_in_tar + target.offset
        payload_hi = payload_lo + len(target.data)
        checks += 1
        inside = all(payload_lo <= i < payload_hi for i in diffs)
        if not inside:
            failures += 1
            print("FAIL  changed bytes fall outside the target payload range")
        else:
            print(
                f"PASS  all changed bytes inside target payload "
                f"[{payload_lo:#x}, {payload_hi:#x})"
            )

        # 5. the patched image must re-parse with identical structure
        p_members = fw.parse_tar(patched)
        checks += 1
        o_names = [m.name for m in members]
        p_names = [m.name for m in p_members]
        if o_names != p_names:
            failures += 1
            print(f"FAIL  member list changed: {o_names} -> {p_names}")
        else:
            print("PASS  member list unchanged")

        checks += 1
        p_img = fw.parse_qspi(next(m for m in p_members if "C1C" in m.name).data)
        o_img = fw.parse_qspi(c1c.data)
        same_layout = (
            [(e.name, e.offset, e.size) for e in o_img.entries]
            == [(e.name, e.offset, e.size) for e in p_img.entries]
        )
        if not same_layout:
            failures += 1
            print("FAIL  entry table layout changed")
        else:
            print(f"PASS  entry table layout unchanged ({len(p_img.entries)} entries)")

        # 6. the other three members must be byte-identical
        checks += 1
        others_ok = True
        for om, pm in zip(members, p_members):
            if "C1C" in om.name:
                continue
            if om.data != pm.data:
                others_ok = False
                print(f"FAIL  unrelated member changed: {om.name}")
        if others_ok:
            print("PASS  other three members byte-identical")

        # 7. and the patched payload must be readable back out
        checks += 1
        rt = next(e for e in p_img.entries if e.name.strip() == "qspi_ver_def.h")
        if rt.data != patched_payload:
            failures += 1
            print("FAIL  patched payload did not round-trip out of the image")
        else:
            print("PASS  patched payload round-trips out of the rebuilt image")

    print()
    print(f"{checks - failures}/{checks} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

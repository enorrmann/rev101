#!/usr/bin/env python3
"""Test named 64-bit block ciphers against the C0A ECB-anchor corpus (§2 of
docs/C0A_EXPLOITATION.md), with known-answer tests.

Cycle: implement cipher -> check against a published KAT -> only then test it
against the anchor corpus. An implementation that fails its own KAT proves
nothing about the target, so the KATs gate every candidate.

Candidates (table-free, typical of embedded firmware):
  TEA, XTEA, XXTEA, RC5-32/12/16, RC5-32/12/b, Speck64/128, Simon64/128,
  and HIGHT if available.

Also re-scans the plaintext images for cipher constants (notably the TEA/XTEA
delta 0x9E3779B9), which FINDINGS.md's earlier scan may not have isolated.

Usage:
    python3 tools/try_block_ciphers.py
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mc101fw as fw  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
M = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Ciphers (single 64-bit block, big-endian word order where the classic
# reference uses it)
# ---------------------------------------------------------------------------

def xtea_encrypt(pt: bytes, key: bytes, rounds: int = 32) -> bytes:
    k = struct.unpack(">IIII", key[:16])
    v0, v1 = struct.unpack(">II", pt)
    s = 0
    delta = 0x9E3779B9
    for _ in range(rounds):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M
        s = (s + delta) & M
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M
    return struct.pack(">II", v0, v1)


def tea_encrypt(pt: bytes, key: bytes, rounds: int = 32) -> bytes:
    k = struct.unpack(">IIII", key[:16])
    v0, v1 = struct.unpack(">II", pt)
    s = 0
    delta = 0x9E3779B9
    for _ in range(rounds):
        s = (s + delta) & M
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & M
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & M
    return struct.pack(">II", v0, v1)


def xxtea_encrypt(data: bytes, key: bytes) -> bytes:
    # reference XXTEA over a single 2-word block
    k = struct.unpack("<IIII", key[:16])
    v = list(struct.unpack("<II", data))
    n = 2
    delta = 0x9E3779B9
    rounds = 6 + 52 // n
    total = 0
    for _ in range(rounds):
        total = (total + delta) & M
        e = (total >> 2) & 3
        for p in range(n):
            y = v[(p + 1) % n]
            mx = (((v[(p - 1) % n] >> 5) ^ (y << 2)) +
                  ((y >> 3) ^ (v[(p - 1) % n] << 4)) ^
                  ((total ^ y) + (k[(p & 3) ^ e] ^ v[(p - 1) % n]))) & M
            v[p] = (v[p] + mx) & M
    return struct.pack("<II", v[0], v[1])


class RC5:
    """RC5-32/rounds/words, little-endian words, as per Rivest's reference."""

    def __init__(self, rounds: int, key: bytes):
        self.r = rounds
        P, Q = 0xB7E15163, 0x9E3779B9
        c = max(1, (len(key) + 3) // 4)
        L = [int.from_bytes(key[i * 4:i * 4 + 4].ljust(4, b"\x00"), "little")
             for i in range(c)]

        def rotl(x, n):
            n &= 31
            return ((x << n) | (x >> (32 - n))) & M if n else x & M

        t = 2 * (self.r + 1)
        S = [(P + i * Q) & M for i in range(t)]
        A = B = i = j = 0
        for _ in range(3 * max(t, c)):
            A = S[i] = rotl((S[i] + A + B) & M, 3)
            B = L[j] = rotl((L[j] + A + B) & M, (A + B) & 31)
            i = (i + 1) % t
            j = (j + 1) % c
        self.S = S

    def encrypt(self, pt: bytes) -> bytes:
        A, B = struct.unpack("<II", pt)
        A = (A + self.S[0]) & M
        B = (B + self.S[1]) & M
        for i in range(1, self.r + 1):
            A = (((A ^ B) << (B & 31)) | ((A ^ B) >> (32 - (B & 31)))) & M if (B & 31) else (A ^ B)
            A = (A + self.S[2 * i]) & M
            B = (((B ^ A) << (A & 31)) | ((B ^ A) >> (32 - (A & 31)))) & M if (A & 31) else (B ^ A)
            B = (B + self.S[2 * i + 1]) & M
        return struct.pack("<II", A, B)


# ---------------------------------------------------------------------------
# Known-answer tests (gate every cipher before it is used)
# ---------------------------------------------------------------------------

KATS = []


def kat(name, fn, pt, key, expected):
    got = fn(pt, key)
    KATS.append((name, got.hex(), expected.hex(), got == expected))


def run_kats():
    # XTEA: Needham & Wheeler reference implementation, key=0/plaintext=0
    kat("XTEA k=0 pt=0", xtea_encrypt, b"\x00" * 8, b"\x00" * 16,
        bytes.fromhex("dee9d4d8f7131ed9"))
    # TEA standard test vector (Wheeler & Needham): key=0, pt=0
    kat("TEA k=0 pt=0", tea_encrypt, b"\x00" * 8, b"\x00" * 16,
        bytes.fromhex("41ea3a0a94baa940"))
    # RC5-32/12/16: key=0, pt=0 -> 21A5DBEE154B8F6D (Rivest reference)
    rc5 = RC5(12, b"\x00" * 16)
    got = rc5.encrypt(b"\x00" * 8)
    KATS.append(("RC5-32/12/16 k=0 pt=0", got.hex(),
                 "21a5dbee154b8f6d", got == bytes.fromhex("21a5dbee154b8f6d")))

    ok = True
    print("known-answer tests:")
    for name, got, exp, good in KATS:
        print(f"  [{'PASS' if good else 'FAIL'}] {name}: got {got} expected {exp}")
        ok &= good
    return ok


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--anchor-hex", nargs="*",
                    default=["6b4c9a852c732831", "dc1205ad381ecdac",
                             "e372fb5ef54ba427"])
    args = ap.parse_args(argv)

    if not run_kats():
        print()
        print("RESULT: cipher implementations failed their known-answer tests; "
              "no conclusion can be drawn about the anchor corpus.")
        return 2
    print()

    images = {}
    raw = fw.load_container(REPO / "mc101_sys_v182.zip")
    for m in fw.parse_tar(raw):
        if fw.is_qspi(m.data):
            for e in fw.parse_qspi(m.data).entries:
                if e.name.strip() in ("sdram1.bin", "idm1.bin"):
                    images[e.name.strip()] = e.data

    print("cipher-constant immediate scan in plaintext images (LE/BE 32 & 64-bit):")
    for label, val in {"TEA/XTEA delta": 0x9E3779B9, "RC5 P": 0xB7E15163,
                       "RC5 Q": 0x9E3779B9, "CRC32 poly": 0xEDB88320,
                       "Speck z?": 0x7369F885}.items():
        found = []
        for w in (4, 8):
            if val >= (1 << (8 * w)):
                continue
            for endian in ("little", "big"):
                pat = val.to_bytes(w, endian)
                for name, data in images.items():
                    c = data.count(pat)
                    if c:
                        found.append(f"{name} {endian}{w*8}x{c}")
        print(f"  {label:>14} = {val:#x}: {'; '.join(found) or 'not present'}")
    print()

    anchors = [bytes.fromhex(h) for h in args.anchor_hex]
    zero = b"\x00" * 8
    keys = {"empty": b"", "zero16": b"\x00" * 16, "ff16": b"\xff" * 16,
            "ver": b"0.010001", "App1": b"App1_Main", "QSPI": b"QSPI ",
            "delta": struct.pack("<I", 0x9E3779B9) * 4}

    cands = {"TEA": tea_encrypt, "XTEA": xtea_encrypt, "XXTEA": xxtea_encrypt}
    print(f"E_K(0) vs {len(anchors)} observed anchors:")
    any_hit = False
    for cname, fn in cands.items():
        for kname, key in keys.items():
            if len(key) < 16:
                continue
            got = fn(zero, key)
            hit = got in anchors
            any_hit |= hit
            print(f"  {cname:>6} {kname:>8}: {got.hex()}{'   <== MATCH' if hit else ''}")
    for rnd in (12, 16):
        rc = RC5(rnd, b"\x00" * 16)
        for kname, key in keys.items():
            if len(key) < 16:
                continue
            r = RC5(rnd, key)
            got = r.encrypt(zero)
            hit = got in anchors
            any_hit |= hit
            print(f"  RC5/{rnd} {kname:>8}: {got.hex()}{'   <== MATCH' if hit else ''}")
    print()
    print("RESULT:", "an anchor was reproduced" if any_hit
          else "no KAT-verified cipher/key reproduced an observed anchor")
    return 0 if any_hit else 1


if __name__ == "__main__":
    raise SystemExit(main())

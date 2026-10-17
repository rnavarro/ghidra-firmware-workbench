#!/usr/bin/env python3
"""Compare the compiled SLEIGH semantics (executed through Ghidra's pcode
emulator, out-emu/*.csv) against k0emu's own handlers.

ADJBA/ADJBS: adj-emu.csv vs adjb-table.csv
ROL4/ROR4:   rol4-emu.csv vs a table driven straight out of k0emu
"""
import csv
import os
import sys

# GFW_WORKDIR holds adjb-table.csv, out-emu/adj-emu.csv and out-emu/rol4-emu.csv.
# K0EMU_SRC is the checkout of the reference emulator (k0emu).
BASE = os.environ.get("GFW_WORKDIR", os.getcwd())
sys.path.insert(0, os.environ["K0EMU_SRC"])
from k0emu.processor import Flags, Registers, RegisterPairs  # noqa: E402
from k0emu.system import make_processor  # noqa: E402


def k0_rol4_ror4():
    """Drive k0emu's own ROL4/ROR4 over 256 A x 256 [HL]."""
    mem_addr = 0xFB00  # high-speed RAM, well clear of the SFR page
    out = []
    for name, fn in (
        ("ROL4", "_opcode_0x31_0x80_rol4"),
        ("ROR4", "_opcode_0x31_0x90_ror4"),
    ):
        # one processor per instruction; ROL4/ROR4 touch only A, (HL) and the
        # cycle counter, so re-seeding A/(HL) each case leaves no state behind.
        p = make_processor()
        for a_in in range(256):
            for mem_in in range(256):
                p.write_gp_reg(Registers.A, a_in)
                p.write_gp_regpair(RegisterPairs.HL, mem_addr)
                p.write_memory(mem_addr, mem_in)
                getattr(p, fn)(0x80)
                out.append(
                    (
                        name,
                        a_in,
                        mem_in,
                        p.read_gp_reg(Registers.A),
                        p.read_memory(mem_addr),
                    )
                )
    return out


def cmp_adj():
    bad = 0
    total = 0
    seen = set()
    with open(f"{BASE}/adjb-table.csv") as f:
        want = {(r["instr"], r["a_in"], r["cy_in"], r["ac_in"]): r for r in csv.DictReader(f)}
    assert len(want) == 2048, f"truth table has {len(want)} rows, expected 2048"
    with open(f"{BASE}/out-emu/adj-emu.csv") as f:
        for r in csv.DictReader(f):
            total += 1
            k = (r["instr"], r["a_in"], r["cy_in"], r["ac_in"])
            if k in seen:
                raise SystemExit(f"duplicate case in adj-emu.csv: {k}")
            seen.add(k)
            if k not in want:
                raise SystemExit(f"adj-emu.csv emitted a case the emulator never produced: {k}")
            w = want[k]
            for col in ("a_out", "cy_out", "ac_out", "z_out"):
                if r[col] != w[col]:
                    bad += 1
                    if bad <= 5:
                        print(f"ADJ MISMATCH {k} {col}: sleigh={r[col]} k0emu={w[col]}")
                    break
    if total != 2048 or len(seen) != 2048:
        raise SystemExit(f"adj-emu.csv has {total} rows / {len(seen)} unique, expected 2048")
    print(f"ADJBA/ADJBS: {total - bad}/{total} match (sleigh-pcode vs k0emu), coverage 2048/2048")
    return bad


def cmp_rol():
    want = k0_rol4_ror4()
    got = []
    with open(f"{BASE}/out-emu/rol4-emu.csv") as f:
        for r in csv.DictReader(f):
            got.append(
                (r["instr"], int(r["a_in"]), int(r["mem_in"]), int(r["a_out"]), int(r["mem_out"]))
            )
    # explicit length check: zip() would silently pass on a truncated prefix
    if len(got) != 131072:
        raise SystemExit(f"rol4-emu.csv has {len(got)} rows, expected 131072")
    if len(want) != len(got):
        raise SystemExit(f"k0emu table has {len(want)} rows but sleigh has {len(got)}")
    bad = 0
    n = 0
    for i in range(len(got)):
        n += 1
        if got[i] != want[i]:
            bad += 1
            if bad <= 5:
                print(f"ROT MISMATCH row {i}: sleigh={got[i]} k0emu={want[i]}")
    print(f"ROL4/ROR4: {n - bad}/{n} match (sleigh-pcode vs k0emu), rows compared={n}")
    return bad


if __name__ == "__main__":
    b = cmp_adj() + cmp_rol()
    raise SystemExit(1 if b else 0)

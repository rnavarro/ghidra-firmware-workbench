#!/usr/bin/env python3
"""Drive k0emu's own ADJBA/ADJBS handlers over all 1024 A/cy/ac combinations.

Truth comes from the emulator, never from a hand-written table.
CSV columns: instr,a_in,cy_in,ac_in,a_out,cy_out,ac_out,z_out
"""
import csv
import os
import sys

# K0EMU_SRC is the checkout of the reference emulator (k0emu).
sys.path.insert(0, os.environ["K0EMU_SRC"])
from k0emu.processor import Flags, Registers  # noqa: E402
from k0emu.system import make_processor  # noqa: E402

OUT = os.environ.get("GFW_ADJB_TABLE",
                     os.path.join(os.environ.get("GFW_WORKDIR", os.getcwd()), "adjb-table.csv"))

rows = []
for name, fn in (
    ("ADJBA", "_opcode_0x61_0x80_adjba"),
    ("ADJBS", "_opcode_0x61_0x90_adjbs"),
):
    for a_in in range(256):
        for cy_in in (0, 1):
            for ac_in in (0, 1):
                p = make_processor()
                p.write_gp_reg(Registers.A, a_in)
                p.write_psw((cy_in << 0) | (ac_in << 4))
                getattr(p, fn)(0x80)
                psw = p.read_psw()
                rows.append(
                    dict(
                        instr=name,
                        a_in=a_in,
                        cy_in=cy_in,
                        ac_in=ac_in,
                        a_out=p.read_gp_reg(Registers.A),
                        cy_out=(psw & Flags.CY) >> 0,
                        ac_out=(psw & Flags.AC) >> 4,
                        z_out=(psw & Flags.Z) >> 6,
                    )
                )

with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)

print(f"wrote {len(rows)} rows to {OUT}")
for name in ("ADJBA", "ADJBS"):
    sub = [r for r in rows if r["instr"] == name]
    print(
        f"{name}: {len(sub)} rows, a_out distinct={sorted({r['a_out'] for r in sub})[:8]}..., "
        f"cy_out values={sorted({r['cy_out'] for r in sub})}, "
        f"ac_out values={sorted({r['ac_out'] for r in sub})}"
    )

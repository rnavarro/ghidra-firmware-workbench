#!/usr/bin/env python3
"""Independent Python model of the ADJBA/ADJBS constructors now in 78K0.sinc.

This transcribes the SLEIGH control flow (the goto/label structure), not
k0emu's if/if structure, so that a 1024/1024 match against the k0emu-derived
CSV is evidence the transcription is faithful in both directions.
"""
import csv
import os

CSV = os.environ.get("GFW_ADJB_TABLE",
                     os.path.join(os.environ.get("GFW_WORKDIR", os.getcwd()), "adjb-table.csv"))


def adjba(a_in, cy, ac):
    """Model of :ADJBA is op16_07=0b01100001 & op16_815=0b10000000 { ... }

    Mirrors the SLEIGH goto/label structure one label at a time:
        if (ac != 0) goto <adjba_ac1>;
        if (lo > 9) goto <adjba_ac0_lowgt9>;
        if (cy != 0) goto <adjba_add60>;
        if (hi < 10) goto <adjba_apply>;
        goto <adjba_add60>;
    <adjba_ac0_lowgt9>   nac = 1; if (cy==0 && hi<9) delta=0x06 else {ncy=1; delta=0x66;}
    <adjba_ac1>          if (cy==0 && hi<10) delta=0x06 else {ncy=1; delta=0x66;}
    <adjba_add60>        ncy = 1; delta = 0x60;
    <adjba_apply>        A = A + delta; CY=ncy; AC=nac; Z=(A==0);
    """
    lo = a_in & 0x0F
    hi = (a_in >> 4) & 0x0F
    delta = 0x00
    ncy = 0
    nac = 0
    if ac != 0:
        pass  # falls through the first three tests to <adjba_ac1>
    elif lo > 9:
        nac = 1
        if cy != 0 or hi >= 9:
            ncy = 1
            delta = 0x66
        else:
            delta = 0x06
        a_out = (a_in + delta) & 0xFF
        return a_out, ncy, nac, int(a_out == 0)
    elif cy != 0 or hi >= 10:
        ncy = 1
        delta = 0x60
        a_out = (a_in + delta) & 0xFF
        return a_out, ncy, nac, int(a_out == 0)
    else:
        a_out = (a_in + delta) & 0xFF  # <adjba_apply> with delta 0
        return a_out, ncy, nac, int(a_out == 0)
    # <adjba_ac1>
    if cy != 0 or hi >= 10:
        ncy = 1
        delta = 0x66
    else:
        delta = 0x06
    a_out = (a_in + delta) & 0xFF
    return a_out, ncy, nac, int(a_out == 0)


def adjbs(a_in, cy, ac):
    """Model of :ADJBS is op16_07=0b01100001 & op16_815=0b10010000 { ... }"""
    delta = 0x00
    ncy = 0
    if ac != 0:
        # <adjbs_ac1>
        if cy == 0:
            delta = 0x06
        else:
            ncy = 1
            delta = 0x66
    else:
        if cy != 0:
            ncy = 1
            delta = 0x60
    a_out = (a_in - delta) & 0xFF
    return a_out, ncy, 0, 1 if a_out == 0 else 0


def main():
    bad = []
    total = 0
    with open(CSV) as f:
        for r in csv.DictReader(f):
            total += 1
            fn = adjba if r["instr"] == "ADJBA" else adjbs
            got = fn(int(r["a_in"]), int(r["cy_in"]), int(r["ac_in"]))
            want = (
                int(r["a_out"]),
                int(r["cy_out"]),
                int(r["ac_out"]),
                int(r["z_out"]),
            )
            if got != want:
                bad.append((r, got, want))
    print(f"compared {total} rows; mismatches={len(bad)}")
    for r, got, want in bad[:10]:
        print("MISMATCH", r, "model=", got, "emu=", want)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())

# Verifying compiled SLEIGH semantics against a reference emulator

The problem: a SLEIGH constructor can be wrong in ways the tooling will not report. It compiles,
it decodes, it produces p-code, and the p-code is not what the part does. `unimpl` at least
leaves a marker; a wrong body leaves nothing. Reading the `.sinc` against the manual catches
transcription slips. It does not catch a body that reads plausibly and computes the wrong thing.

This document describes the harness that does catch those, the numbers it produced on a 78K0
module, and what it cannot tell you.

## Method

1. Compile the language with the shipped compiler, from a scratch copy of its directory:
   `support/sleigh 78K0.slaspec`. A compile with zero errors is a precondition, not a result.
2. Build a small binary blob holding the instruction under test, one instance per instruction, at
   known offsets. Here: `0x00 ADJBA (61 80)`, `0x02 ADJBS (61 90)`, `0x04 ROL4 (31 80)`,
   `0x06 ROR4 (31 90)`, 16 bytes of scratch after them.
3. Import the blob with the module's language and run `AdjVerify.java`, which drives Ghidra's
   own p-code emulator over the instruction and writes CSV.
4. Build the same table from the reference emulator, and compare cell by cell in Python.

The point of driving Ghidra's emulator rather than reimplementing the semantics in Python is that
the evidence is about the compiled `.sla`. A Python restatement of the constructor proves only
that the restatement agrees with itself.

`AdjVerify` covers:

- `ADJBA` and `ADJBS` over 256 values of A times CY times AC: 1024 cases each, 2048 total. Output
  columns are `a_out, cy_out, ac_out, z_out`.
- `ROL4` and `ROR4` over 256 values of A times 256 values of `[HL]`: 65536 cases each, 131072
  total. Output columns are `a_out, mem_out`. `HL` is pointed at a scratch byte inside the blob
  so the read-modify-write has somewhere to land.

The reference side is `python/dump_adjb.py` for ADJBA/ADJBS and the `k0_rol4_ror4` function in
`python/compare_emu.py` for ROL4/ROR4, both driving k0emu's own handlers. `python/model_adjb.py`
is a third, independent check: it transcribes the SLEIGH control flow (the goto/label structure),
not the reference emulator's if/if structure, so agreement in both directions is evidence the
transcription is faithful rather than accidentally equivalent on the sampled inputs.

Both comparison scripts check row counts and uniqueness before comparing. A truncated CSV would
otherwise pass as a prefix match.

## Results

| Instructions | Cases | Agreement |
|---|---|---|
| `ADJBA`, `ADJBS` | 2048 | 2048 of 2048 |
| `ROL4`, `ROR4` | 131072 | 131072 of 131072 |

The `ROL4` number is the one that found a defect. The original constructor exchanged the two
nibbles on the store: it computed `*HL = (alo << 4) | hl_lo`, while the part computes
`(HL)7-4 <- (HL)3-0` and `(HL)3-0 <- A3-0`, that is `*HL = (hl_lo << 4) | alo`. Against hardware
behaviour that form matched in 4096 of 65536 cases, which is consistent with matching only when
the two nibbles happen to be equal or the swap is otherwise invisible. The corrected form agrees
in 65536 of 65536.

`ROR4` was checked the same way and was correct as it stood, which is the useful control: the
harness does not report every instruction as broken.

Three constructors in total produced p-code that disagreed with the part, and none of them raised
anything a user would notice. No `UNIMPLEMENTED` marker, no compile warning, no decompiler error.
The decompiled output read normally. The three were `MOV1 <saddr>.bit, CY`, which could set a bit
with `OR` but never clear one; `MOV1 <0xFF00-page saddr>.bit, CY`, whose body was commented out so
the instruction consumed its bytes and ran no p-code at all; and `ROL4 [HL]` above.

Separately, 38 constructors carried `unimpl`. Those are the visible failure mode: each one
truncates control flow where it appears, and on this image `OR1 CY,A.7` alone occurs 18 times and
cut ten decompiled functions short.

## The migration off `EmulatorHelper`

The first version of the harness ran on `ghidra.app.emulator.EmulatorHelper`, which is
`@Deprecated(since="12.1", forRemoval=true)`. The shipped replacement is
`ghidra.pcode.emu.PcodeEmulator`, demonstrated in
`Ghidra/Features/SystemEmulation/ghidra_scripts/StandAloneEmuExampleScript.java`.

`PcodeEmulator` is language-level and has no program attached, so the script copies every
initialized memory block into `emulator.getSharedState()` before the first step, sets `A`, `PSW`,
`HL` and `PC` through `thread.getState().setVar(...)`, calls `thread.reInitialize()` to load the
program counter, and then `thread.stepInstruction()`. Values are converted with
`ghidra.pcode.utils.Utils.longToBytes` using the language's endianness, which avoids getting the
byte order wrong for the 16-bit `HL` register.

Verification of the migration was by output equality, not by inspection: the CSV written by the
migrated script is byte-for-byte identical to the CSV written by the `EmulatorHelper` version
(`diff` over `adj-emu.csv`, 2049 lines, and `rol4-emu.csv`, 131073 lines). Re-running the
comparison against the same reference table gave the same 2048 of 2048, and the ROL4/ROR4
comparison regenerated both tables and gave 131072 of 131072.

## Negative result: Decompiler Parameter ID makes this image worse

Measured 2026-10-17 on the 78K0/KC2 image, 202 functions, identical seeds and analysis
options to the baseline run. `DecompilerParameterIdCmd` then ran over all executable memory
in 2.6 s and committed signatures.

| metric | baseline | with PDI |
|---|---|---|
| signatures changed | n/a | 111 of 202 |
| functions gaining parameters | n/a | 98 |
| parameters lost | n/a | 0 |
| functions turned `void` | n/a | 0 |
| implicit `in_AX` inputs | 54 | 82 |
| total implicit register noise | 110 | 138 |
| functions returning `undefined1` | 40 | 40 |
| decompiled C, lines | 11,220 | 11,514 |

It adds parameters and increases register noise. It fixes nothing.

### Why

The `.cspec` declares one prototype, `__asmA`, with `strategy="register"` over A, BC, HL and
DE, output A. When the analyzer decides a function takes parameters it binds them to those
registers, and because A is declared first every invented parameter materialises as an
`in_AX` read. PDI therefore does not replace implicit register inputs; it manufactures more
of them.

The clearest fabricated case is `crt0`, the reset entry at `0x04B0`, which has zero call sites
in the image and acquired `char param_1`. There is no call site that could supply it.

The 40 `undefined1` returns are unaffected because a single catch-all prototype is as
ambiguous about the return side as about parameters.

### Consequence

Do not add PDI to the pipeline for this module. The limiting factor is not a missing analyzer;
it is that one catch-all prototype cannot express a convention that hand-written assembly does
not follow. Any improvement has to come from the `.cspec`, which means either more than one
prototype or register inputs declared as conditionally read rather than always read.

`PdiProbe.java` in `scripts/` reproduces the measurement. It runs the analysis stage itself,
because `-noanalysis` leaves only the seeded functions and PDI would have almost nothing to
explore.

## Limits

- The reference is a separate emulator (k0emu) whose behaviour was captured from a physical
  uPD78F0831Y, not a live logic analyser on the target part. If the reference is wrong, the
  comparison is confidently wrong in the same direction. It is a second implementation, not
  hardware in the loop.
- The reference part is a different 78K0 variant than the image under analysis (uPD79F8513A,
  78K0/KC2). Instructions checked here are common to both, but this harness does not establish
  that any variant-specific instruction is right.
- Only four instructions are covered exhaustively. The other constructors were checked against
  the manual, which is weaker evidence than a truth table.
- `SEL RBn` writes the register-bank-select bits but does not redirect subsequent register reads,
  because SLEIGH has no register-bank model. No p-code test can express the real behaviour, so
  this harness cannot test it at all.
- `ROL4` and `ROR4` raise on a `0xFF00`-page operand on the part. SLEIGH cannot express that
  restriction, so both decode normally and the harness cannot distinguish the cases.
- The harness tests one instruction in isolation with hand-set inputs. It says nothing about
  instruction sequences, flags carried across instructions, or interrupts.

## Reproducing

```
# compile the language (scratch copy; do not edit the install)
cp -r <ghidra>/Ghidra/Processors/78K0/data/languages /tmp/languages
cd /tmp/languages && <ghidra>/support/sleigh 78K0.slaspec

# run the p-code side
analyzeHeadless /tmp/proj t -import blob.bin -processor 78K0:LE:16:default -noanalysis \
  -scriptPath scripts -postScript AdjVerify.java /tmp/out

# build the reference tables, then compare
python3 python/dump_adjb.py          # needs K0EMU_SRC
python3 python/compare_emu.py        # needs GFW_WORKDIR and K0EMU_SRC
```

Both Python scripts read `GFW_WORKDIR` (default: the current directory) and `K0EMU_SRC` (no
default; the checkout of the reference emulator). `compare_emu.py` prints the two agreement
fractions above and exits non-zero on any mismatch.

## Extensions

Ghidra ships optional extensions as zips under `Extensions/Ghidra/` and only loads one after it
is unpacked into `Ghidra/Extensions/`. That directory is inside the install and outside any
language-directory check, so an extension installed on one machine and not another is drift a
`.sinc` diff will never show.

`extensions.want` records the extensions a documented workflow needs. The Makefile installs
from the shipped zips and verifies against that list:

```
make list-extensions                 # what this Ghidra ships
make extensions EXTENSION=MachineLearning
make verify-extensions               # non-zero if a wanted extension is missing
```

Only `MachineLearning` is listed. It provides the RandomForest function finder, which is not
used on the worked example (function recovery there is already complete) but is the fallback
for an image with neither a vector table nor an external disassembler to seed from.

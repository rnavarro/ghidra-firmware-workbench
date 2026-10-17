# Ghidra firmware workbench

Scripts for reversing raw 8-bit MCU firmware with headless Ghidra, developed against a Renesas
78K0/KC2 image (uPD79F8513A, 32 KiB flash) and applicable to any architecture where the input is
a flat dump and the language module knows the instruction set but not the code layout.

Everything here runs from `analyzeHeadless`; nothing needs the GUI. The scripts are Apache-2.0.
See `NOTICE` for provenance.

```
scripts/
  SeedFromK0dasm.java      seed function boundaries from an external disassembler's entry list
  FullDisasmGuarded.java   guarded full pass: flat listing, named functions, decompiled C
  AlignmentScore.java      score every phase offset in a 64-byte window
  PrepImage.java           earlier exploratory pass (block execute + Aggressive Instruction Finder)
  AdjVerify.java           drive compiled SLEIGH p-code over an exhaustive input table
  entries/78k0-uPD79F8513A.txt  example entry list with the format explained
python/
  dump_adjb.py             dump the reference emulator's ADJBA/ADJBS truth table
  model_adjb.py            independent Python model of the ADJBA/ADJBS constructors
  compare_emu.py           compare Ghidra p-code output against the reference tables
docs/
  seeding.md               the seeding technique in full
  verification.md          the p-code harness, what it proved, what it does not
```

## 1. Three ways Ghidra appears to do nothing

Each of these produces a plausible-looking program with little or no analysis, no error, and no
obvious next step.

### No entry points

A raw binary has no symbols, so auto-analysis has nothing to start from. The Aggressive
Instruction Finder is off by default, and it will not run until roughly twenty functions already
exist (Ghidra issue #8386). On a fresh import the function count is zero, so enabling it changes
nothing. The signature is a listing with no instructions outside whatever block the loader
disassembled at import, and an analysis log that finishes without complaint.

Fix: create real functions first, by one of the methods in `docs/seeding.md`. Twenty functions
from real code are enough to satisfy the precondition; twenty functions of decoded data are worse
than none, because the finder will extend them.

### Flash mapped non-executable

The 78K0 module declares its flash blocks non-executable at import, so a seed that lands in one
can be skipped without a word. Analysis-time entry-point disassembly honours the execute flag by
default (`OperandReferenceAnalyzer`, "Respect Execute Flag" is true). Script-level
`disassemble(Address)` honours it only when the program option "Restrict Disassembly to
Executable Memory" is set. Measured on 12.1.4, in the refusing state the signature is a success
return and no instruction: `disassemble()` returned true but `getInstructionAt()` returned null,
and `CreateFunctionCmd.applyTo()` returned true with a null status message. Nothing is logged.

Fix: `setExecute(true)` on every block a seed can land in, before seeding. `SeedFromK0dasm` does
this as its first step.

### `unimpl` truncating control flow

A constructor whose body is `unimpl` still decodes, still consumes its bytes, and still appears in
the listing as a normal instruction. It emits one `UNIMPLEMENTED` p-code op, so the decompiler
stops there: no fall-through, no `RETURN`, no writeback. Interrupt handlers end in `halt_baddata`.
On this image, 38 constructors carried `unimpl`, and `OR1 CY,A.7` alone occurs 18 times and cut ten
decompiled functions short.

The signature is in the listing text, not in the log: `grep -c UNIMPLEMENTED` over a p-code dump
or a look at the decompiled function tails. Fix: implement the constructor, or at minimum decode
the instruction and mark the missing semantics explicitly rather than leaving `unimpl`.

Three further constructors produced wrong p-code with no `UNIMPLEMENTED` marker at all; see
`docs/verification.md`.

## 2. Seeding beats alignment brute force

Alignment scoring is the fallback for when nothing external can name an address. It works by
disassembling from each of 64 phase offsets and scoring the result on SFR-reference coherence: real
code touches a small set of peripheral registers repeatedly, while a misaligned walk scatters
references and dies. On this image that sweep picked `0x0417` with 13425 instructions, 94 percent
coverage and 70 distinct SFRs.

`0x0417` is inside a descending 16-bit constant table (`0x0400-0x04AF`). The decode is coherent
because the table's low bytes form valid opcodes, and the walk happens to end exactly at `0x04B0`,
where real code starts, so it reaches the whole application. What it cannot do is mark `0x04B0` as
a function entry: `crt0` stays inside the table's function, and 33 instructions of the table are
committed as code, including one `CALLF` and three `CALLT` instructions that exist only as data.
The score cannot tell a coherent table from code, because on 8-bit MCU images a table of 16-bit
values looks like a long run of valid instructions.

An external disassembler that has already recovered entry points gives boundaries rather than
guesses. `SeedFromK0dasm` reads a `hexaddr name` list and turns each entry into a function with
`CreateFunctionCmd`, after enabling execute on the blocks. On this image that is eight seeds
(`crt0`, `main`, six ISRs) instead of one phase guess, and every one is a real boundary. The
alignment sweep remains in the repo as the fallback for images where no external disassembler
exists.

The full technique, including the vector-table case and the phantom-call hazard, is in
`docs/seeding.md`.

## 3. Do not trust the named-function export alone

`FullDisasmGuarded` writes three outputs: `disassembly.txt` (grouped by function),
`flat-disassembly.txt` (linear over the whole listing) and `decompiled.c`. The named-function
export is the one that hides defects. On this image it omitted `crt0` at `0x04B0` entirely and
stopped at `0x0525`, because the seeding walk had entered that code mid-stream inside another
function's body. Grepping the flat listing found the entry immediately.

Treat the function list as a view, not as ground truth. Diff the flat listing against the function
bodies; anything present in the flat listing and absent from the export is either a boundary that
was never created or code absorbed into a neighbour.

## 4. `EmulatorHelper` is going away

`ghidra.app.emulator.EmulatorHelper` is `@Deprecated(since="12.1", forRemoval=true)`. Use
`ghidra.pcode.emu.PcodeEmulator`. Ghidra ships a minimal working example at
`Ghidra/Features/SystemEmulation/ghidra_scripts/StandAloneEmuExampleScript.java`, and its own
differential test harness (`ghidra.test.processors.support.EmulatorTestRunner`) already runs on
`PcodeEmulator`.

`AdjVerify.java` in this repo is on `PcodeEmulator`. `PcodeEmulator` is language-level, so it has
no program attached: the image bytes have to be copied into `getSharedState()` before the first
step, and registers are set through `thread.getState().setVar(...)` followed by
`thread.reInitialize()` and `thread.stepInstruction()`. Migrating it changed the output by zero
bytes: the CSV from the migrated script is identical to the CSV the `EmulatorHelper` version
produced, so the comparison results did not move.

## 5. Prior art

I found no published prior art for external-disassembler-guided boundary seeding combined with
alignment scoring on 8-bit MCU images. The components are documented and should be cited:

- Seeding functions from an address list with `CreateFunctionCmd` is a well-trodden API pattern;
  see Ghidra Discussions #3615 and the r/ghidra thread on creating functions from a dictionary.
- BYTEWEIGHT (Bao et al., USENIX Security 2014) is the standard reference for statistical
  entry-point and function identification, and supplies the vocabulary for what alignment scoring
  does here. It is not guided by a second disassembler.
- `mdomanic/ghidra-fw-toolkit` (MIT) has the same shape as the seeding pipeline: a host-side
  profile of the image, consumed inside Ghidra to apply memory maps and landmarks. It targets ARM
  Cortex-M only, and has no external disassembler and no alignment scoring.

What is ours: the combination of a second disassembler's entry list with `CreateFunctionCmd`
seeding, the SFR-coherence alignment score as a fallback, the block-execute handling that makes
both work on a non-executable flash map, and the differential p-code harness in
`docs/verification.md`. Nothing in this repo was copied from a GPL processor module.

## 6. Worked example

The module developed alongside these scripts is the 78K0 fork at
`https://github.com/rnavarro/Ghidra-78K0-Processor-Module`. It is GPL-3.0 and is a separate work;
no code from it is copied here. The scripts treat it as an installed language, the same way they
would treat any other Ghidra language module.

## Running

```
# seed from an entry list, then dump everything
analyzeHeadless <proj> <name> -import fw.bin -processor 78K0:LE:16:default \
  -loader BinaryLoader -loader-baseAddr 0x0 -noanalysis \
  -preScript SeedFromK0dasm.java scripts/entries/78k0-uPD79F8513A.txt

analyzeHeadless <proj> <name> -process fw.bin -noanalysis \
  -postScript FullDisasmGuarded.java /tmp/out 0x04b0
```

`FullDisasmGuarded` clears block 0 (`0x0000-0x03FF`) and keeps it non-executable, because on this
image block 0 is a flash-loader payload rather than OEM content. Adjust that range for images whose
reset vector and startup code are intact.

`AdjVerify` needs a blob containing the four instructions to test and the module's compiled
`.sla`:

```
analyzeHeadless <proj> <name> -import blob.bin -processor 78K0:LE:16:default -noanalysis \
  -postScript AdjVerify.java /tmp/out
python3 python/compare_emu.py
```

`compare_emu.py` needs a reference emulator and a truth table; see `docs/verification.md` for what
that reference was and how to point the scripts at yours.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

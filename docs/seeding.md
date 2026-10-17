# Seeding a raw 8-bit image

The problem this document solves: a flat firmware dump has bytes but no structure, and Ghidra's
analysis is driven by structure. Everything below is about manufacturing correct starting points
cheaply, and about the ways a wrong starting point looks like a right one.

Worked example throughout: a 32 KiB Renesas 78K0/KC2 image (uPD79F8513A) whose block 0
(`0x0000-0x03FF`) was overwritten by a flash-loader payload before the dump was taken.

## (a) Why a raw image has no entry points

Auto-analysis starts from three things: the loader's entry point, symbols, and references it can
derive from already-decoded instructions. A `BinaryLoader` import supplies none of them. The
program has one memory block, zero functions, zero instructions, and no entry point in the symbol
table.

The Aggressive Instruction Finder would be the tool for this, but it refuses to run below roughly
twenty existing functions (Ghidra issue #8386). With zero functions, enabling it is a no-op. The
same applies to "Function Start Search". The analysis completes, logs nothing unusual, and leaves
the listing empty. This is the first "Ghidra does nothing" failure.

There is a second-order problem specific to masked MCU images: block 0 usually holds the reset
vector, the interrupt vector table and the CALLT table. When block 0 is erased or, as here,
replaced by our own loader, the on-chip tables that would normally supply entry points are gone.
The bytes that survive are application code with no table pointing at it.

## (b) Vector-table seeding when the table survives

If the vector table is intact, it is the cheapest correct source. A vector table is an array of
addresses at a known base; each non-blank entry is a handler entry, and on most 8-bit parts the
reset slot points at startup code.

Procedure:

1. Read the table at its documented base with the documented entry size and endianness.
2. Discard entries that are blank (`0xFF` on 78K0, `0x00` on some parts) or that point outside
   flash.
3. Discard duplicate targets: several sources often share one handler.
4. Create a function at each remaining target, and name it from the vector slot.

Cautions:

- A vector table entry may point at a one-byte `RETI` stub rather than a real handler. That is
  still a valid function boundary.
- Tables can be relocated or partially erased. A table that decodes into addresses outside the
  flash range is not a table; stop and use (c).
- On 78K0 the CALLT table at `0x0040` and the CALLF table at `0x0800` are separate from the
  interrupt vectors and are equally good boundary sources when intact.

On this image none of that applies: block 0 is our payload, so every table that could seed the
analysis is either absent or actively misleading. Trusting the bytes at `0x0000` decodes the
loader, not the OEM firmware, and the loader's reset path leads into loader code that does not
exist in the OEM image.

## (c) External-disassembler seeding when the table does not survive

When the tables are gone, a standalone disassembler can still recover boundaries, because it can
be seeded from a reconstructed vector table, from known compiler startup patterns, or by hand from
a listing. The output that matters is a list of code entry addresses.

`SeedFromK0dasm.java` consumes that list and creates a function at each address:

1. Enable execute on every block, so the disassembler will touch them (see (d)).
2. For each entry, disassemble at the address if no instruction exists there yet.
3. Apply `CreateFunctionCmd` at the address. The command follows the instruction flow and builds
   the function body.
4. Rename the function if the list supplied a name.
5. Treat an existing instruction at the address as success, so re-running the script is idempotent.

The command reports failure through `getStatusMsg()` rather than an exception, and a null status
with no function created is the silent case described in (d). The script prints both the status
and whether a function actually appeared.

### Entry-list format

One entry per line, `hexaddr name`. The address may be written `0x04b0` or `04b0`; `$` is also
accepted. A `#` starts a comment anywhere on the line, including after the name. A line with only
an address creates an unnamed function.

```
# Entry points for the example uPD79F8513A image (78K0/KC2).
# Format: <hexaddr> <name>

04b0 crt0
1d0b main
4d5c INTSR0     # UART0 receive
4dc3 INTST0     # UART0 transmit
4ded INTTM51
524c INTP1
52d6 INTP3
52e9 INTTMH0
```

`scripts/entries/78k0-uPD79F8513A.txt` is this list in full. Eight entries were enough: they satisfy
the finder's precondition with functions at real boundaries, and the analysis extends from them.

Two properties make this worth doing before any analysis pass:

- Every seed is a real boundary. The alternative, one guessed phase offset, produces one function
  that starts in the middle of something.
- Seeds are independent. A bad entry costs one function; a bad phase offset costs the alignment of
  every instruction that follows it.

## (d) The block-execute requirement

The 78K0 module declares its flash blocks non-executable. Measured on a fresh import of this
image, the module's blocks are `flash:0000` (vector table), `flash:0040` (CALLT table),
`flash:0080` and `flash:1000` (program), `flash:0800` (CALLF table), `flash:f000`, `flash:f400`,
`flash:f800`, `flash:fb00` (RAM), `flash:ff00` (SFR), all with execute false. Only the block the
raw loader created is executable.

Two different mechanisms can then skip your seeds, and neither announces itself:

- Analysis-time entry-point disassembly. `OperandReferenceAnalyzer` defaults "Respect Execute
  Flag" to true and calls `PseudoDisassembler.setRespectExecuteFlag(true)`, so it refuses to
  decode into a non-executable block.
- Script-level disassembly, conditionally. `disassemble(Address)` builds a `DisassembleCommand`,
  which consults the program option "Restrict Disassembly to Executable Memory"
  (`Disassembler.RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY`). That option defaults to
  false, so on 12.1.4 an unconditional `disassemble()` may still decode a non-executable block.
  With the option on, the refusal is exact and silent: `disassemble()` returned true,
  `getInstructionAt()` returned null, `CreateFunctionCmd.applyTo()` returned true with a null
  status message, and nothing was written to the log.

The fix is the same either way and costs one loop:

```java
for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
    if (!b.isExecute()) {
        try { b.setExecute(true); } catch (Exception e) { }
    }
}
```

`SeedFromK0dasm` runs this before reading the first entry. `FullDisasmGuarded` runs the inverse
after seeding, turning block 0 back off so its payload is not decoded as OEM code.

If a seed silently fails, check three things in this order: was execute set on the block, is the
address inside an initialized block, and did `getInstructionAt()` return non-null after the call.

## (e) Alignment scoring as the fallback

When no external source of boundaries exists, the only option is to guess a start and score the
result. Instruction alignment on these parts is one byte, so a 64-byte window covers every phase
that can matter for the first 64 bytes of code.

`AlignmentScore.java` walks `0x0400` through `0x043F`. For each phase it clears the listing, seeds
`disassemble()` once at that offset, and records:

- total instructions decoded,
- bytes covered,
- number of SFR references in the instruction text (pattern `0xff[0-9a-f]{2}`),
- number of distinct SFR addresses referenced.

The score rests on a property of real code: firmware touches a small set of peripheral registers
repeatedly (timer, UART, ADC, port latches), and a misaligned walk scatters references across many
addresses or dies quickly. High coverage with a small distinct-SFR set is the signature of a
correct phase.

The cost is 64 full clear-and-redisassemble passes per image, plus judgement. On this image the
winner was `0x0417` with 13425 instructions, 94 percent coverage and 70 distinct SFRs.

That result is also the cautionary tale, see (f). The score cannot distinguish code from data that
decodes coherently, and it optimises for coverage, which rewards a walk that happens to run from a
table into real code.

## (f) The phantom-call hazard

A seed inside a table manufactures instructions that no human wrote. On this image `0x0400` is
inside a 256-entry, little-endian, strictly descending table of 16-bit ADC values (the NTC
linearisation table; its first 173 entries were in the erased block 0, so the surviving tail runs
from `0x0400` to `0x04AF`). Seeding at `0x0417` produced:

- 33 instructions inside `0x0400-0x04AF`,
- 4 call-class instructions: one `CALLF !0xad3` and three `CALLT` (`[0x60]`, `[0x5e]`, `[0x64]`),
- a walk whose last instruction ends exactly at `0x04B0`, the true `crt0` entry.

The mechanism is worth stating plainly. Table entries are 16-bit values; a seed that lands on the
low byte of an entry decodes that byte as an opcode. Values in the `0xC1-0xFF` range are `CALLT`
opcodes on 78K0, and the surviving tail is full of them (`0xE1`, `0xDF`, ...). So a descending
table of sensor constants becomes a descending series of table-indirect calls. Because `CALLT`
reads its target from the CALLT table, the phantom call also creates references and can pull the
analysis into unrelated code.

The damage is not the 33 bogus instructions. It is that `crt0` is absorbed: the walk arrives at
`0x04B0` mid-stream, so no function boundary is created there, and the named-function export then
omits `crt0` and stops at `0x0525`. The listing looks continuous and reasonable, and the entry
point is missing.

Detection:

- Grep the flat listing for `CALLT` and `CALLF` in a region you believe is data.
- A run of calls whose targets cluster in one table is a decoded table, not code.
- A function whose first instruction has no predecessor and whose body starts mid-sequence is a
  boundary that was never created.

Prevention:

- Never seed inside a region whose content is monotone, periodic, or dense in `0xC1-0xFF` bytes.
  Check the bytes at the seed before trusting a score.
- Prefer boundaries from an external source, which knows the table's extent.
- When using the alignment score, require that the winning phase be corroborated by at least one
  independent signal: a call target, a branch target, or a known startup pattern such as
  `MOVW SP,#...` at the head of the function.

On this image the corroboration came from k0dasm, which places real code at `0x04B0`; the seeding
list uses that address and the table is left as data.

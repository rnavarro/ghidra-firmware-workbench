// Seed a raw-image Ghidra analysis from entry points recovered outside Ghidra.
//
// A raw dump has no entry points, and on this image the vector table cannot
// supply them: block 0 (0x0000-0x03FF) is our flash-loader payload, not OEM
// content. k0dasm was seeded instead from the reconstructed KC2 vector table
// (hp-oem-firmware/reconstructed/k0dasm_kc2.py, KC2_VECTORS) and derived six live
// ISR targets plus crt0 and main from the surviving code.
//
// This script takes that list and turns each entry into a real function object, so
// the analysis and the decompiler start where the code actually starts instead of
// guessing an alignment. Run it BEFORE the analysis pass; see FullDisasmGuarded.
//
// args: <entries-file>   lines of "<hexaddr> <name>", '#' comments allowed.
//                        A bare "<hexaddr>" line creates an unnamed function.

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

public class SeedFromK0dasm extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) {
            println("usage: SeedFromK0dasm.java <entries-file>");
            return;
        }
        // The 78K0 module maps flash non-executable at import, and disassemble()/
        // createFunction() both refuse a non-executable block. Enable it for every
        // block a seed falls in (all seeds are above block 0, which a later pass
        // turns back off as data).
        for (ghidra.program.model.mem.MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isExecute()) {
                try { b.setExecute(true); } catch (Exception e) { }
            }
        }
        Listing listing = currentProgram.getListing();
        BufferedReader r = new BufferedReader(new FileReader(new File(a[0])));
        int made = 0, skipped = 0;
        String line;
        while ((line = r.readLine()) != null) {
            line = line.trim();
            int hash = line.indexOf('#');
            if (hash >= 0) {
                line = line.substring(0, hash).trim();
            }
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split("\\s+", 2);
            long off = Long.parseLong(parts[0].replace("0x", "").replace("$", ""), 16);
            String name = parts.length > 1 ? parts[1].trim() : null;
            Address addr = toAddr(off);
            try {
                // An existing instruction here means an earlier pass already decoded
                // it; keep that and only add the function, so this stays idempotent.
                if (listing.getInstructionAt(addr) == null) {
                    disassemble(addr);
                }
                Function fn = getFunctionAt(addr);
                if (fn == null) {
                    ghidra.app.cmd.function.CreateFunctionCmd cmd =
                            new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                    boolean ok = cmd.applyTo(currentProgram, monitor);
                    if (!ok) {
                        println("createFunction " + parts[0] + ": " + cmd.getStatusMsg());
                    }
                    fn = getFunctionAt(addr);
                    if (fn != null && name != null) {
                        fn.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                    }
                }
                if (fn != null) {
                    made++;
                } else {
                    skipped++;
                    println("no function at " + parts[0] + " (instruction present: "
                            + (listing.getInstructionAt(addr) != null) + ")");
                }
            } catch (Exception e) {
                skipped++;
                println("seed failed at " + parts[0] + ": " + e.getMessage());
            }
        }
        r.close();
        println("seeded " + made + " functions, " + skipped + " skipped");
    }
}

// Full disassembly of the raw 78K0 image: find a real alignment, seed the analysis from it,
// then let the aggressive instruction finder extend it.
//
// The alignment step matters. A raw image has no entry points, so the analysis has nothing
// to start from and the AIF refuses to run until ~20 functions exist. Disassembling from a
// phase offset that produces coherent code creates those functions from REAL code, which
// both seeds the analysis and satisfies the AIF precondition. 0x0417 was the winner of a
// 64-phase sweep (13425 instructions, 94% coverage, 70 distinct SFRs).
//
// args: <outdir> [align hex]
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.List;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.File;
import java.io.PrintWriter;
import java.util.Map;

public class FullDisasmGuarded extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        File outdir = new File(a.length > 0 ? a[0] : "/tmp/ghidra-out");
        outdir.mkdirs();
        // Extra seeds matter: a single seed leaves holes, and one of them swallowed 1.4 KB
        // containing both serial drivers. Seeds are the alignment winner plus the start of
        // each hole found by scanning for gaps larger than an instruction.
        long align = a.length > 1 ? Long.parseLong(a[1].replace("0x", ""), 16) : 0x0417L;
        // Extra seeds: args 3..n (hex) override the built-in defaults, so a caller can
        // supply the OEM entry points recovered by k0dasm instead of guessing.
        long[] extraSeeds = {0x06dbL, 0x4d5cL, 0x78aeL};
        if (a.length > 2) {
            java.util.List<Long> extra = new java.util.ArrayList<Long>();
            for (int i = 2; i < a.length; i++) {
                extra.add(Long.valueOf(Long.parseLong(a[i].replace("0x", ""), 16)));
            }
            extraSeeds = new long[extra.size()];
            for (int i = 0; i < extra.size(); i++) { extraSeeds[i] = extra.get(i).longValue(); }
        }

        // Block 0 (0x0000-0x03FF) is OUR dump payload, not OEM code: its reset vector,
        // CALLT table and startup code are the loader we flashed, so any analysis that
        // trusts them decodes garbage. Keep it non-executable and clear whatever the
        // importer/earlier analysis put there.
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            boolean blockZero = b.getStart().getOffset() < 0x0400L;
            try {
                b.setExecute(!blockZero);
            } catch (Exception e) { }
        }
        try { clearListing(toAddr(0x0000L), toAddr(0x03FFL)); } catch (Exception e) { }
        println("blocks executable (block 0 excluded)");

        // Real code first: this is what gives the analysis something to follow.
        try { disassemble(toAddr(align)); } catch (Exception e) { }
        for (int i = 0; i < extraSeeds.length; i++) {
            try { disassemble(toAddr(extraSeeds[i])); } catch (Exception e) { }
        }
        Listing ls = currentProgram.getListing();
        int nseeded = 0;
        InstructionIterator si = ls.getInstructions(true);
        while (si.hasNext()) { si.next(); nseeded++; }
        println("instructions after alignment seed: " + nseeded);

        // disassemble() does not create functions, and the AIF refuses to run below ~20.
        // Create them at call/branch targets: those are real code boundaries, not guesses.
        List<ghidra.program.model.address.Address> targets =
                new ArrayList<ghidra.program.model.address.Address>();
        InstructionIterator ti = ls.getInstructions(true);
        while (ti.hasNext()) {
            Instruction ins = ti.next();
            String t = ins.toString().toLowerCase();
            if (t.startsWith("call") || t.startsWith("br !") || t.startsWith("callf")) {
                for (int op = 0; op < ins.getNumOperands(); op++) {
                    Reference[] rs = ins.getOperandReferences(op);
                    for (int i = 0; i < rs.length; i++) {
                        if (rs[i].getToAddress() != null) targets.add(rs[i].getToAddress());
                    }
                }
            }
        }
        for (int i = 0; i < targets.size(); i++) {
            try {
                if (getFunctionAt(targets.get(i)) == null) { createFunction(targets.get(i), null); }
            } catch (Exception e) { }
        }
        int f0 = currentProgram.getFunctionManager().getFunctionCount();
        println("functions after alignment seed: " + f0 + " (from " + targets.size() + " call/branch targets)");

        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
        Map<String, String> opts = getCurrentAnalysisOptionsAndValues(currentProgram);
        String aif = "Aggressive Instruction Finder";
        if (mgr.getAnalyzer(aif) != null && opts.containsKey(aif)) {
            setAnalysisOption(currentProgram, aif, "true");
        }
        String fss = "Function Start Search";
        if (mgr.getAnalyzer(fss) != null && opts.containsKey(fss)) {
            setAnalysisOption(currentProgram, fss, "true");
        }

        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        mgr.startAnalysis(mon);
        mgr.waitForAnalysis(null, mon);

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        println("functions after analysis: " + fm.getFunctionCount());
        int n = 0;
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext()) { it.next(); n++; }
        println("instructions after analysis: " + n);

        PrintWriter w = new PrintWriter(new File(outdir, "disassembly.txt"));
        for (Function fn : fm.getFunctions(true)) {
            AddressSetView body = fn.getBody();
            w.println();
            w.println(";; " + fn.getName() + "  " + fn.getEntryPoint()
                      + "  (" + body.getNumAddresses() + " bytes)");
            InstructionIterator ii = listing.getInstructions(body, true);
            while (ii.hasNext()) {
                Instruction ins = ii.next();
                w.println(ins.getAddress() + "  " + ins.toString());
            }
        }
        w.close();
        println("disassembly.txt written");

        PrintWriter flat = new PrintWriter(new File(outdir, "flat-disassembly.txt"));
        InstructionIterator fi = listing.getInstructions(true);
        while (fi.hasNext()) {
            Instruction ins = fi.next();
            flat.println(ins.getAddress() + "  " + ins.toString());
        }
        flat.close();
        println("flat-disassembly.txt written");

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        PrintWriter d = new PrintWriter(new File(outdir, "decompiled.c"));
        int done = 0, fails = 0;
        for (Function fn : fm.getFunctions(true)) {
            try {
                DecompileResults r = dec.decompileFunction(fn, 60, mon);
                if (r != null && r.decompileCompleted()) {
                    done++;
                    d.println();
                    d.println("/* ---- " + fn.getName() + " @ " + fn.getEntryPoint() + " ---- */");
                    d.println(r.getDecompiledFunction().getC());
                } else { fails++; }
            } catch (Exception e) { fails++; }
        }
        d.close();
        println("decompiled: " + done + ", failures: " + fails);
    }
}

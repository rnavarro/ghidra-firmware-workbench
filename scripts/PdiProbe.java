// @category Probe
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.util.*;

public class PdiProbe extends GhidraScript {
    public void run() throws Exception {
        String out = getScriptArgs()[0];
        boolean commitVoid = getScriptArgs().length > 1 && getScriptArgs()[1].equals("void");

        FunctionManager fm = currentProgram.getFunctionManager();
        println("PROBE seeded=" + fm.getFunctionCount() + " commitVoid=" + commitVoid);

        // Make blocks executable and clear block 0, exactly as FullDisasmGuarded does,
        // so this run is comparable to the measured baseline.
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            try { b.setExecute(true); } catch (Exception e) { }
        }
        try { clearListing(toAddr(0x0000L), toAddr(0x03FFL)); } catch (Exception e) { }

        // Disassemble from the entry point plus the extra seeds.
        String[] extra = new String[] { "06db", "4d5c", "4dc3", "4ded", "4ea8",
            "4f70", "5013", "50cf", "51b9", "524c", "52d6", "52e9", "78ae", "4091", "04b0" };
        try { disassemble(toAddr(0x04b0L)); } catch (Exception e) { }
        for (String h : extra) {
            try { disassemble(toAddr(Long.parseLong(h, 16))); } catch (Exception e) { }
        }

        // Create functions at call/branch targets: real code boundaries, and the AIF
        // refuses to run below ~20 functions.
        List<Address> targets = new ArrayList<>();
        InstructionIterator ti = currentProgram.getListing().getInstructions(true);
        while (ti.hasNext()) {
            Instruction ins = ti.next();
            String t = ins.toString().toLowerCase();
            if (t.startsWith("call") || t.startsWith("br !") || t.startsWith("callf")) {
                for (int op = 0; op < ins.getNumOperands(); op++) {
                    for (Reference r : ins.getOperandReferences(op)) {
                        if (r.getToAddress() != null) targets.add(r.getToAddress());
                    }
                }
            }
        }
        for (Address a : targets) {
            try { if (getFunctionAt(a) == null) createFunction(a, null); } catch (Exception e) { }
        }
        println("PROBE functionsAfterSeed=" + fm.getFunctionCount()
            + " from " + targets.size() + " targets");

        // Run analyzers first: with -noanalysis only the seeded functions exist,
        // so PDI would have almost nothing to explore.
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
        String nr = "Non-Returning Functions - Discovered";
        if (mgr.getAnalyzer(nr) != null && opts.containsKey(nr)) {
            setAnalysisOption(currentProgram, nr, "true");
        }
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        mgr.startAnalysis(mon);
        mgr.waitForAnalysis(null, mon);
        int nAfter = fm.getFunctionCount();
        println("PROBE functionsAfterAnalysis=" + nAfter);

        // Snapshot after analysis, before PDI.
        Map<String, String> before = new LinkedHashMap<>();
        for (Function f : fm.getFunctions(true)) {
            before.put(f.getEntryPoint().toString(), f.getSignature().getPrototypeString());
        }

        AddressSet exec = new AddressSet();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (b.isExecute()) exec.addRange(b.getStart(), b.getEnd());
        }
        println("PROBE execBytes=" + exec.getNumAddresses());

        DecompilerParameterIdCmd cmd = new DecompilerParameterIdCmd(
            "Probe PDI", exec, SourceType.ANALYSIS, true, commitVoid, 60);
        long t0 = System.currentTimeMillis();
        boolean ok = cmd.applyTo(currentProgram, mon);
        long dt = System.currentTimeMillis() - t0;
        println("PROBE PDI applyTo=" + ok + " ms=" + dt + " msg=" + cmd.getStatusMsg());

        int changed = 0, becameVoid = 0, gained = 0, lost = 0;
        List<String> samples = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            String a = before.get(f.getEntryPoint().toString());
            if (a == null) continue;
            String b = f.getSignature().getPrototypeString();
            if (a.equals(b)) continue;
            changed++;
            int pa = countParams(a), pb = countParams(b);
            if (pb > pa) gained++;
            if (pb < pa) lost++;
            if (b.startsWith("void ")) becameVoid++;
            if (samples.size() < 15) samples.add(f.getName() + "  [" + a + "]  ->  [" + b + "]");
        }
        println("PROBE changed=" + changed + " gained=" + gained
            + " lost=" + lost + " becameVoid=" + becameVoid);

        // Dump decompiled C after PDI so it can be diffed against the baseline run.
        ghidra.app.decompiler.DecompInterface di = new ghidra.app.decompiler.DecompInterface();
        di.openProgram(currentProgram);
        PrintWriter dc = new PrintWriter(new File(out, "decompiled-pdi.c"));
        int nOk = 0, nFail = 0;
        for (Function f : fm.getFunctions(true)) {
            dc.println("// " + f.getName() + "  " + f.getEntryPoint()
                + "  (" + f.getBody().getNumAddresses() + " bytes)");
            dc.println("// sig: " + f.getSignature().getPrototypeString());
            ghidra.app.decompiler.DecompileResults r =
                di.decompileFunction(f, 60, mon);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                dc.println(r.getDecompiledFunction().getC());
                nOk++;
            } else {
                dc.println("// DECOMPILE FAILED");
                nFail++;
            }
            dc.println();
        }
        dc.close();
        di.dispose();
        println("PROBE decompiled ok=" + nOk + " fail=" + nFail);

        PrintWriter w = new PrintWriter(new File(out, "pdi-report.txt"));
        w.println("functionsAfterAnalysis=" + nAfter);
        w.println("changed=" + changed + " gained=" + gained
            + " lost=" + lost + " becameVoid=" + becameVoid);
        w.println("applyTo=" + ok + " ms=" + dt);
        w.println();
        for (String s : samples) w.println(s);
        w.close();
        println("PROBE done");
    }

    private int countParams(String sig) {
        int i = sig.indexOf('(');
        int j = sig.lastIndexOf(')');
        if (i < 0 || j < i) return 0;
        String inner = sig.substring(i + 1, j).trim();
        if (inner.isEmpty() || inner.equals("void")) return 0;
        int n = 1;
        for (int k = 0; k < inner.length(); k++) if (inner.charAt(k) == ',') n++;
        return n;
    }
}

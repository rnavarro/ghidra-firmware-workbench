// Prepare a raw 78K0 image for analysis, then report what the analysis achieved.
//
// Facts taken from documentation, not guessed:
//   * "Aggressive Instruction Finder" is OFF by default, and per Ghidra issue #8386 it will
//     not run until ~20 functions already exist;
//   * the 78K0 module maps flash NON-executable and "Disassemble Entry Points.Respect
//     Execute Flag" defaults true, so nothing is treated as code;
//   * a raw image has no entry points, and this dump's vector/CALLT tables are OURS
//     (block 0 is the payload), so they cannot be used for seeding.
//
// The option API (getCurrentAnalysisOptionsAndValues / setAnalysisOption / getAnalyzer) and
// the seed-ordering concern follow the Ghidra bridge in morluto/rea, read locally.
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.Map;

public class PrepImage extends HeadlessScript {
    @Override
    public void run() throws Exception {
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isExecute()) {
                try {
                    b.setExecute(true);
                } catch (Exception e) {
                    println("could not set execute on " + b.getName());
                }
            }
        }
        println("blocks executable");

        Map<String, String> before = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (Map.Entry<String, String> e : before.entrySet()) {
            String k = e.getKey().toLowerCase();
            if (k.contains("instruction") || k.contains("function start") || k.contains("disassemble")) {
                println("  option: " + e.getKey() + " = " + e.getValue());
            }
        }

        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
        String aif = "Aggressive Instruction Finder";
        if (mgr.getAnalyzer(aif) != null && before.containsKey(aif)) {
            setAnalysisOption(currentProgram, aif, "true");
            println("AIF now = " + getCurrentAnalysisOptionsAndValues(currentProgram).get(aif));
        } else {
            println("AIF not present under '" + aif + "'");
        }

        // Seeds exist only to satisfy the AIF's ~20-function precondition. They must sit
        // where the FILE has bytes: a raw binary leaves RAM unbacked, so the module's
        // 0xF400+ area decodes nothing. Both regions used here are free to mangle - block 0
        // holds OUR payload, and block 31 is blank - and both are excluded from the dump
        // comparison, so bogus code created there cannot contaminate the analysis.
        int seeded = 0;
        long[] regions = {0x0100L, 0x7C00L};
        for (long base : regions) {
            for (long a = base; a < base + 0x100 && seeded < 24; a += 2) {
                try {
                    disassemble(toAddr(a));
                    if (createFunction(toAddr(a), null) != null) {
                        seeded++;
                    }
                } catch (Exception e) {
                    // undecodable at that offset; only the count matters here
                }
            }
        }
        println("seeds created: " + seeded);

        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        mgr.startAnalysis(mon);
        mgr.waitForAnalysis(null, mon);
        println("functions after: " + currentProgram.getFunctionManager().getFunctionCount());
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        int n = 0;
        while (it.hasNext()) { it.next(); n++; }
        println("instructions after: " + n);
    }
}

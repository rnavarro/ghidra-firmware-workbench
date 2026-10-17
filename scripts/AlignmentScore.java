// Find the correct disassembly alignment for a raw 78K0 image.
//
// A raw image has no entry points, so every start is a guess. Code that is real has a
// signature a wrong walk does not: it stays coherent across a long run, it references a
// SMALL set of SFR addresses repeatedly (the timer, UART, ADC, ports), and it covers a lot
// of the image through control flow. A misaligned walk decodes into nonsense, scatters
// SFR references randomly, and dies. Trying every phase offset in a 64-byte window covers
// every possible instruction alignment.
//
// args: <out csv>
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import java.io.File;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AlignmentScore extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String out = a.length > 0 ? a[0] : "/tmp/align.csv";
        PrintWriter w = new PrintWriter(new File(out));
        w.println("start,instr,funcs,sfr_refs,distinct_sfr,covered");
        Listing listing = currentProgram.getListing();

        for (long start = 0x0400; start < 0x0440; start++) {
            try {
                clearListing(toAddr(0x0400), toAddr(0x7BFF));
            } catch (Exception e) {
                // nothing to clear on the first pass
            }
            try {
                disassemble(toAddr(start));
            } catch (Exception e) {
                // undefined at this offset
            }
            int ninstr = 0;
            int sfr = 0;
            int covered = 0;
            Set<String> distinct = new HashSet<>();
            InstructionIterator it = listing.getInstructions(true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                ninstr++;
                covered += ins.getLength();
                Matcher m = Pattern.compile("0xff[0-9a-f]{2}").matcher(ins.toString().toLowerCase());
                while (m.find()) {
                    sfr++;
                    distinct.add(m.group());
                }
            }
            w.println(String.format("0x%04x,%d,%d,%d,%d,%d",
                    start, ninstr,
                    currentProgram.getFunctionManager().getFunctionCount(),
                    sfr, distinct.size(), covered));
            w.flush();
        }
        w.close();
        println("wrote " + out);
    }
}

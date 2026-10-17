// Drive the compiled 78K0 SLEIGH pcode over exhaustive operand/flag combinations
// for ADJBA, ADJBS, ROL4 and ROR4, and dump CSV.
//
// Evidence that the *shipped* .sla semantics, not a Python restatement, match
// the k0emu truth table.
//
// Runs on ghidra.pcode.emu.PcodeEmulator. The older ghidra.app.emulator
// .EmulatorHelper is @Deprecated(since="12.1", forRemoval=true); this script
// needs nothing from it. Because PcodeEmulator is language-level rather than
// program-level, the image bytes are copied into the emulator's shared state
// before the first step.
//
// args: <outdir> [blob-base-hex]
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.PrintWriter;

public class AdjVerify extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        File outdir = new File(a.length > 0 ? a[0] : "/tmp/ghidra-78k0-fix");
        outdir.mkdirs();
        long base = a.length > 1 ? Long.parseLong(a[1].replace("0x", ""), 16) : 0L;

        // Blob layout: 0x00 ADJBA (61 80), 0x02 ADJBS (61 90),
        //              0x04 ROL4  (31 80), 0x06 ROR4  (31 90)
        String[] names = { "ADJBA", "ADJBS", "ROL4", "ROR4" };
        long[] pcs = { 0x00L, 0x02L, 0x04L, 0x06L };
        for (long pc : pcs) {
            Address ad = toAddr(base + pc);
            if (getInstructionAt(ad) == null) {
                disassemble(ad);
            }
            Instruction ins = getInstructionAt(ad);
            println(String.format("%04x: %s len=%d", pc, ins == null ? "NULL" : ins.toString(),
                ins == null ? -1 : ins.getLength()));
        }

        SleighLanguage language = (SleighLanguage) currentProgram.getLanguage();
        boolean be = language.isBigEndian();
        AddressSpace space = language.getDefaultSpace();
        PcodeEmulator emu = new PcodeEmulator(language);
        PcodeThread<byte[]> thread = emu.newThread();

        // PcodeEmulator has no program attached: seed its shared state with every
        // initialized block of the imported image so the decoder and [HL] loads see
        // the same bytes the listing does.
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized()) {
                continue;
            }
            long size = b.getSize();
            if (size <= 0 || size > Integer.MAX_VALUE - 8) {
                continue;
            }
            byte[] bytes = new byte[(int) size];
            b.getBytes(b.getStart(), bytes);
            emu.getSharedState().setVar(b.getStart().getAddressSpace(),
                b.getStart().getOffset(), bytes.length, true, bytes);
        }

        Register regA = language.getRegister("A");
        Register regPSW = language.getRegister("PSW");
        Register regHL = language.getRegister("HL");
        Register regPC = language.getProgramCounter();
        final long scratch = base + 0x10L;  // [HL] scratch byte, inside the blob block

        // The emulator's thread state is what the p-code reads and writes. Every
        // case rewrites A, PSW, HL and PC, and ADJBA/ADJBS/ROL4/ROR4 touch nothing
        // else, so no per-case reset beyond those is needed.
        thread.overrideContextWithDefault();

        // ---- ADJBA / ADJBS: 1024 cases each -----------------------------------
        PrintWriter w = new PrintWriter(new File(outdir, "adj-emu.csv"));
        w.println("instr,a_in,cy_in,ac_in,a_out,cy_out,ac_out,z_out");
        for (int k = 0; k < 2; k++) {
            for (int aIn = 0; aIn < 256; aIn++) {
                for (int cy = 0; cy < 2; cy++) {
                    for (int ac = 0; ac < 2; ac++) {
                        long psw = cy | (ac << 4);
                        thread.getState().setVar(regA, Utils.longToBytes(aIn,
                            regA.getMinimumByteSize(), be));
                        thread.getState().setVar(regPSW, Utils.longToBytes(psw,
                            regPSW.getMinimumByteSize(), be));
                        thread.getState().setVar(regPC, Utils.longToBytes(base + pcs[k],
                            regPC.getMinimumByteSize(), be));
                        thread.reInitialize();
                        try {
                            thread.stepInstruction();
                        } catch (Exception e) {
                            println("STEP FAILED " + names[k] + ": " + e.getMessage());
                            throw new RuntimeException("emulator step failed", e);
                        }
                        long aOut = Utils.bytesToLong(
                            thread.getState().getVar(regA, Reason.INSPECT), 1, be) & 0xFF;
                        long pswOut = Utils.bytesToLong(
                            thread.getState().getVar(regPSW, Reason.INSPECT), 1, be) & 0xFF;
                        w.println(String.format("%s,%d,%d,%d,%d,%d,%d,%d", names[k], aIn, cy, ac,
                            aOut, pswOut & 1, (pswOut >> 4) & 1, (pswOut >> 6) & 1));
                    }
                }
            }
        }
        w.close();
        println("adj-emu.csv written");

        // ---- ROL4 / ROR4: 256 A x 256 [HL] -----------------------------------
        w = new PrintWriter(new File(outdir, "rol4-emu.csv"));
        w.println("instr,a_in,mem_in,a_out,mem_out");
        for (int k = 2; k < 4; k++) {
            for (int aIn = 0; aIn < 256; aIn++) {
                for (int memIn = 0; memIn < 256; memIn++) {
                    thread.getState().setVar(regA, Utils.longToBytes(aIn,
                        regA.getMinimumByteSize(), be));
                    thread.getState().setVar(regHL, Utils.longToBytes(scratch,
                        regHL.getMinimumByteSize(), be));
                    emu.getSharedState().setVar(space, scratch, 1, true,
                        new byte[] { (byte) memIn });
                    thread.getState().setVar(regPC, Utils.longToBytes(base + pcs[k],
                        regPC.getMinimumByteSize(), be));
                    thread.reInitialize();
                    try {
                        thread.stepInstruction();
                    } catch (Exception e) {
                        println("STEP FAILED " + names[k] + ": " + e.getMessage());
                        throw new RuntimeException("emulator step failed", e);
                    }
                    long aOut = Utils.bytesToLong(
                        thread.getState().getVar(regA, Reason.INSPECT), 1, be) & 0xFF;
                    long memOut = Utils.bytesToLong(thread.getState()
                        .getVar(space.getAddress(scratch), 1, false, Reason.INSPECT), 1, be) & 0xFF;
                    w.println(String.format("%s,%d,%d,%d,%d", names[k], aIn, memIn, aOut, memOut));
                }
            }
        }
        w.close();
        println("rol4-emu.csv written");
    }
}

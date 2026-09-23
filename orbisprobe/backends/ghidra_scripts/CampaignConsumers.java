// Campaign pass 2: decompile the consumer functions of the P1 candidates.
// @category OrbisProbe

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

public class CampaignConsumers extends GhidraScript {
    private static final long[] TARGETS = {
        Long.parseUnsignedLong("ffffffffd00d0ac0", 16),
        Long.parseUnsignedLong("ffffffffd00d9520", 16),
        Long.parseUnsignedLong("ffffffffd00d96e0", 16),
        Long.parseUnsignedLong("ffffffffd0138fb0", 16),
        Long.parseUnsignedLong("ffffffffd0182980", 16),
        Long.parseUnsignedLong("ffffffffd01d8460", 16),
        Long.parseUnsignedLong("ffffffffd01e0820", 16),
        Long.parseUnsignedLong("ffffffffd03159b0", 16),
        Long.parseUnsignedLong("ffffffffd0362970", 16),
        Long.parseUnsignedLong("ffffffffd03631b0", 16),
        Long.parseUnsignedLong("ffffffffd038d4e0", 16),
        Long.parseUnsignedLong("ffffffffd038d5a0", 16),
        Long.parseUnsignedLong("ffffffffd038d6a0", 16),
        Long.parseUnsignedLong("ffffffffd03b0510", 16),
        Long.parseUnsignedLong("ffffffffd041a680", 16),
        Long.parseUnsignedLong("ffffffffd041cc60", 16),
        Long.parseUnsignedLong("ffffffffd041dce0", 16),
        Long.parseUnsignedLong("ffffffffd043e7e0", 16),
        Long.parseUnsignedLong("ffffffffd0448a80", 16),
        Long.parseUnsignedLong("ffffffffd0448d30", 16),
        Long.parseUnsignedLong("ffffffffd04b48a0", 16),
        Long.parseUnsignedLong("ffffffffd04b4990", 16),
        Long.parseUnsignedLong("ffffffffd04d66b0", 16),
        Long.parseUnsignedLong("ffffffffd04d6870", 16),
        Long.parseUnsignedLong("ffffffffd05699c0", 16),
        Long.parseUnsignedLong("ffffffffd06e3b90", 16),
        Long.parseUnsignedLong("ffffffffd06e4b80", 16),
        Long.parseUnsignedLong("ffffffffd06e4c80", 16),
        Long.parseUnsignedLong("ffffffffd06e5070", 16),
        Long.parseUnsignedLong("ffffffffd06e5250", 16),
        Long.parseUnsignedLong("ffffffffd06e5300", 16),
        Long.parseUnsignedLong("ffffffffd06e5400", 16),
        Long.parseUnsignedLong("ffffffffd06e55b0", 16),
        Long.parseUnsignedLong("ffffffffd06e7fd0", 16),
        Long.parseUnsignedLong("ffffffffd076cf00", 16),
        Long.parseUnsignedLong("ffffffffd0777380", 16),
        Long.parseUnsignedLong("ffffffffd0781430", 16),
        Long.parseUnsignedLong("ffffffffd07818c0", 16),
        Long.parseUnsignedLong("ffffffffd0798550", 16),
        Long.parseUnsignedLong("ffffffffd07e3fe0", 16),
        Long.parseUnsignedLong("ffffffffd07f0650", 16),
        Long.parseUnsignedLong("ffffffffd07f0820", 16),
        Long.parseUnsignedLong("ffffffffd07f0880", 16),
        Long.parseUnsignedLong("ffffffffd080c610", 16),
        Long.parseUnsignedLong("ffffffffd080f870", 16),
        Long.parseUnsignedLong("ffffffffd0815820", 16),
        Long.parseUnsignedLong("ffffffffd083c8c0", 16),
        Long.parseUnsignedLong("ffffffffd083d050", 16),
        Long.parseUnsignedLong("ffffffffd083d110", 16),
        Long.parseUnsignedLong("ffffffffd083d1d0", 16),
        Long.parseUnsignedLong("ffffffffd083d2a0", 16)
    };

    private static String esc(String v) {
        if (v == null) return "";
        StringBuilder o = new StringBuilder();
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '\\') o.append("\\\\");
            else if (c == '"') o.append("\\\"");
            else if (c == '\n') o.append("\\n");
            else if (c == '\r') o.append("\\r");
            else if (c < 0x20) o.append(' ');
            else o.append(c);
        }
        return o.toString();
    }

    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/tmp/consumers.json";
        Set<Function> functions = new LinkedHashSet<>();
        for (long t : TARGETS) {
            Function f = getFunctionContaining(toAddr(t));
            if (f != null) functions.add(f);
        }
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        StringBuilder sb = new StringBuilder("{\"functions\":{");
        boolean first = true;
        for (Function f : functions) {
            DecompileResults r = dec.decompileFunction(f, 25, monitor);
            if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) continue;
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            int insns = 0;
            while (ii.hasNext()) { ii.next(); insns++; }
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(Long.toUnsignedString(f.getEntryPoint().getOffset(), 16))
              .append("\":{\"entry\":\"0x").append(Long.toUnsignedString(f.getEntryPoint().getOffset(), 16))
              .append("\",\"instructions\":").append(insns)
              .append(",\"c\":\"").append(esc(r.getDecompiledFunction().getC())).append("\"}");
        }
        sb.append("}}");
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(outPath), StandardCharsets.UTF_8))) { w.write(sb.toString()); }
        println("CAMPAIGN-CONSUMERS-WRITTEN " + outPath + " functions=" + functions.size());
    }
}

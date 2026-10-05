// OrbisProbe campaign pass: decompile the next P1/P2 candidate functions and their consumers.
// @category OrbisProbe

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class CampaignCandidates extends GhidraScript {
    private static final long[] TARGETS = {
        Long.parseUnsignedLong("ffffffffd041dce0", 16),
        Long.parseUnsignedLong("ffffffffd041dd3c", 16),
        Long.parseUnsignedLong("ffffffffd04d66b0", 16),
        Long.parseUnsignedLong("ffffffffd04d6708", 16),
        Long.parseUnsignedLong("ffffffffd04d6870", 16),
        Long.parseUnsignedLong("ffffffffd04d68c9", 16),
        Long.parseUnsignedLong("ffffffffd05699c0", 16),
        Long.parseUnsignedLong("ffffffffd0569b2f", 16),
        Long.parseUnsignedLong("ffffffffd06e3b90", 16),
        Long.parseUnsignedLong("ffffffffd06e3c2b", 16),
        Long.parseUnsignedLong("ffffffffd0781430", 16),
        Long.parseUnsignedLong("ffffffffd0781523", 16),
        Long.parseUnsignedLong("ffffffffd07e3fe0", 16),
        Long.parseUnsignedLong("ffffffffd07e4093", 16),
        Long.parseUnsignedLong("ffffffffd07f0820", 16),
        Long.parseUnsignedLong("ffffffffd07f085d", 16),
        Long.parseUnsignedLong("ffffffffd07f0880", 16),
        Long.parseUnsignedLong("ffffffffd07f08d3", 16),
        Long.parseUnsignedLong("ffffffffd080f870", 16),
        Long.parseUnsignedLong("ffffffffd080f8ac", 16)
    };

    private static String esc(String value) {
        if (value == null) { return ""; }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\') { out.append("\\\\"); }
            else if (c == '"') { out.append("\\\""); }
            else if (c == '\n') { out.append("\\n"); }
            else if (c == '\r') { out.append("\\r"); }
            else if (c < 0x20) { out.append(' '); }
            else { out.append(c); }
        }
        return out.toString();
    }

    private static String addr(Address a) {
        return a == null ? "null" : "0x" + Long.toUnsignedString(a.getOffset(), 16);
    }

    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/tmp/campaign.json";
        ReferenceManager refs = currentProgram.getReferenceManager();
        Set<Function> interesting = new LinkedHashSet<>();
        for (long target : TARGETS) {
            Function f = getFunctionContaining(toAddr(target));
            if (f != null) {
                interesting.add(f);
                ReferenceIterator it = refs.getReferencesTo(f.getEntryPoint());
                while (it.hasNext()) {
                    Reference r = it.next();
                    if (r.getReferenceType().isCall()) {
                        Function caller = getFunctionContaining(r.getFromAddress());
                        if (caller != null) { interesting.add(caller); }
                    }
                }
            }
        }
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        StringBuilder sb = new StringBuilder("{\"functions\":{");
        boolean first = true;
        for (Function f : interesting) {
            DecompileResults res = dec.decompileFunction(f, 25, monitor);
            if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) { continue; }
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            int insns = 0;
            while (ii.hasNext()) { ii.next(); insns++; }
            if (!first) { sb.append(","); }
            first = false;
            String key = Long.toUnsignedString(f.getEntryPoint().getOffset(), 16);
            sb.append("\"").append(key).append("\":{\"entry\":\"").append(addr(f.getEntryPoint()))
              .append("\",\"instructions\":").append(insns)
              .append(",\"c\":\"").append(esc(res.getDecompiledFunction().getC())).append("\"}");
        }
        sb.append("}}");
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(outPath), StandardCharsets.UTF_8))) {
            w.write(sb.toString());
        }
        println("CAMPAIGN-CANDIDATES-WRITTEN " + outPath + " functions=" + interesting.size());
    }
}

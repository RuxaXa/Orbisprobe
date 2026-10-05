// OrbisProbe LIVE2.7 field/writer/handle exporter. Runs on the EXISTING whole-image project.
// @category OrbisProbe
//
//   * every WRITE to the ops-table index global DAT_ffffffffd1b32cd0 -> index domain
//   * every access (read and write) with displacement 0x21850 -> the callback field
//   * the ioctl-code comparisons inside the gc_ioctl dispatcher
//   * decompiled C for the handle lookup, the candidate initializers and every writer found
// Writes are separated from reads: a writer is never inferred from an xref list.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Live27Field extends GhidraScript {
    private static final long INDEX_GLOBAL = Long.parseUnsignedLong("ffffffffd1b32cd0", 16);
    private static final long DISPATCHER = Long.parseUnsignedLong("ffffffffd05adbf0", 16);
    private static final long[] EXTRA_FUNCTIONS = {
        Long.parseUnsignedLong("ffffffffd0337b00", 16),
        Long.parseUnsignedLong("ffffffffd02e68e0", 16),
        Long.parseUnsignedLong("ffffffffd04f6900", 16),
        Long.parseUnsignedLong("ffffffffd058d730", 16),
        Long.parseUnsignedLong("ffffffffd057d060", 16)
    };
    private static final long FIELD_OFFSET = 0xF8L;
    private static final long CALLBACK_OFFSET = 0x21850L;
    private static final int MAX_DECOMPILE = 26;

    private static String esc(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\') { out.append("\\\\"); }
            else if (c == '"') { out.append("\\\""); }
            else if (c == '\n') { out.append("\\n"); }
            else if (c == '\r') { out.append("\\r"); }
            else if (c == '\t') { out.append("\\t"); }
            else if (c < 0x20) { out.append(' '); }
            else { out.append(c); }
        }
        return out.toString();
    }

    private static String addr(Address address) {
        return address == null ? "null" : "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "/tmp/live27.json";
        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();
        Set<Function> interesting = new LinkedHashSet<>();
        List<String> indexWrites = new ArrayList<>();
        List<String> indexReads = new ArrayList<>();
        List<String> callbackAccesses = new ArrayList<>();
        List<String> fieldF8Writes = new ArrayList<>();
        List<String> ioctlCodes = new ArrayList<>();

        // ---- index global: writes vs reads
        ReferenceIterator indexRefs = refs.getReferencesTo(toAddr(INDEX_GLOBAL));
        while (indexRefs.hasNext()) {
            Reference reference = indexRefs.next();
            Function function = getFunctionContaining(reference.getFromAddress());
            String where = addr(reference.getFromAddress()) + " " + reference.getReferenceType().toString()
                    + " in " + (function == null ? "null" : addr(function.getEntryPoint()));
            if (reference.getReferenceType().isWrite()) {
                indexWrites.add(where);
                if (function != null) {
                    interesting.add(function);
                }
            } else {
                indexReads.add(where);
            }
        }

        // ---- instruction scan: callback offset, field_f8 stores, ioctl codes
        InstructionIterator all = listing.getInstructions(true);
        while (all.hasNext()) {
            Instruction insn = all.next();
            Function function = getFunctionContaining(insn.getAddress());
            String text = insn.toString();
            for (int opIndex = 0; opIndex < insn.getNumOperands(); opIndex++) {
                for (Object object : insn.getOpObjects(opIndex)) {
                    if (!(object instanceof Scalar)) {
                        continue;
                    }
                    long value = ((Scalar) object).getUnsignedValue();
                    if (value == CALLBACK_OFFSET) {
                        boolean write = text.startsWith("MOV") && text.contains("[") && text.indexOf('[')
                                < text.indexOf(',');
                        callbackAccesses.add(esc(addr(insn.getAddress()) + " " + text + "  ("
                                + (write ? "write" : "read/call") + ", fn "
                                + (function == null ? "null" : addr(function.getEntryPoint())) + ")"));
                        if (write && function != null) {
                            interesting.add(function);
                        }
                    }
                    if (value == FIELD_OFFSET && text.startsWith("MOV")
                            && text.indexOf('[') < text.indexOf(',')) {
                        fieldF8Writes.add(esc(addr(insn.getAddress()) + " " + text + "  (fn "
                                + (function == null ? "null" : addr(function.getEntryPoint())) + ")"));
                    }
                    if (value >= 0xC0000000L && value <= 0xCFFFFFFFL
                            && insn.getAddress().getOffset() >= DISPATCHER
                            && insn.getAddress().getOffset() < DISPATCHER + 0x2000) {
                        ioctlCodes.add(esc(addr(insn.getAddress()) + " " + text));
                    }
                }
            }
        }

        for (long extra : EXTRA_FUNCTIONS) {
            Function function = getFunctionContaining(toAddr(extra));
            if (function != null) {
                interesting.add(function);
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Map<String, String> bodies = new LinkedHashMap<>();
        int decompiled = 0;
        for (Function function : interesting) {
            if (decompiled >= MAX_DECOMPILE) {
                break;
            }
            DecompileResults result = decompiler.decompileFunction(function, 25, monitor);
            if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
                continue;
            }
            String key = Long.toUnsignedString(function.getEntryPoint().getOffset(), 16);
            bodies.put(key, "{\"entry\":\"" + addr(function.getEntryPoint()) + "\",\"decompiled_c\":\""
                    + esc(result.getDecompiledFunction().getC()) + "\"}");
            decompiled++;
        }
        decompiler.dispose();

        StringBuilder out = new StringBuilder();
        out.append("{\"index_writes\":[").append(join(indexWrites)).append("]");
        out.append(",\"index_reads_count\":").append(indexReads.size());
        out.append(",\"index_reads_sample\":[").append(join(indexReads.subList(0, Math.min(12, indexReads.size())))).append("]");
        out.append(",\"callback_0x21850\":[").append(join(callbackAccesses)).append("]");
        out.append(",\"field_f8_stores\":[").append(join(fieldF8Writes.subList(0, Math.min(40, fieldF8Writes.size())))).append("]");
        out.append(",\"field_f8_stores_total\":").append(fieldF8Writes.size());
        out.append(",\"ioctl_codes\":[").append(join(ioctlCodes)).append("]");
        out.append(",\"functions\":{");
        boolean first = true;
        for (Map.Entry<String, String> entry : bodies.entrySet()) {
            if (!first) { out.append(","); }
            first = false;
            out.append("\"").append(entry.getKey()).append("\":").append(entry.getValue());
        }
        out.append("}}");

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8))) {
            writer.write(out.toString());
        }
        println("LIVE27-WRITTEN " + outPath + " index_writes=" + indexWrites.size()
                + " callback=" + callbackAccesses.size() + " f8_stores=" + fieldF8Writes.size()
                + " ioctl_codes=" + ioctlCodes.size() + " functions=" + bodies.size());
    }

    private static String join(List<String> values) {
        StringBuilder builder = new StringBuilder();
        boolean first = true;
        for (String value : values) {
            if (!first) { builder.append(","); }
            first = false;
            builder.append("\"").append(value).append("\"");
        }
        return builder.toString();
    }
}

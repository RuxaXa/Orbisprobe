// OrbisProbe LIVE2.6 targeted dispatch/entry exporter. Runs on the EXISTING whole-image project.
// @category OrbisProbe
//
// Answers the remaining closure questions without re-analysing the image:
//   * who references the GPU/ioctl strings (HP3D, EOP, "can not allocate kernel write", gc_ioctl)
//   * which functions touch the large dispatch offset 0x21850 (and its neighbourhood)
//   * who writes/reads the two dispatch globals seen in the ops-table path
//   * decompiled C for every newly discovered function (bounded)

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
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

public class Live26Dispatch extends GhidraScript {
    private static final String[] NEEDLES = {
        "EOP in HP3D ring is not finished",
        "EOP in GFX ring is not finished",
        "can not allocate kernel write",
        "gc_ioctl",
        "W__Build_J02697906_sys_internal__"
    };
    private static final long[] GLOBALS = {
        Long.parseUnsignedLong("ffffffffd1b32cd0", 16),
        Long.parseUnsignedLong("ffffffffd24589a4", 16),
        Long.parseUnsignedLong("ffffffffd24c5d00", 16)
    };
    private static final long NEIGHBOUR_OFFSET = 0x21850L;
    private static final int MAX_DECOMPILE = 20;

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
        String outPath = args.length > 0 ? args[0] : "/tmp/live26.json";
        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();
        Memory memory = currentProgram.getMemory();
        Set<Function> discovered = new LinkedHashSet<>();
        List<Map<String, String>> stringRefs = new ArrayList<>();
        List<Map<String, String>> neighbourAccesses = new ArrayList<>();
        List<Map<String, String>> globalRefs = new ArrayList<>();

        // ---- strings -> addresses -> referencing functions
        for (String needle : NEEDLES) {
            byte[] pattern = needle.getBytes(StandardCharsets.US_ASCII);
            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized()) {
                    continue;
                }
                Address cursor = block.getStart();
                while (cursor != null && cursor.compareTo(block.getEnd()) < 0) {
                    Address found = memory.findBytes(cursor, block.getEnd(), pattern, null, true, monitor);
                    if (found == null) {
                        break;
                    }
                    ReferenceIterator iterator = refs.getReferencesTo(found);
                    while (iterator.hasNext()) {
                        Reference reference = iterator.next();
                        Function function = getFunctionContaining(reference.getFromAddress());
                        Map<String, String> row = new LinkedHashMap<>();
                        row.put("string", needle);
                        row.put("string_address", addr(found));
                        row.put("referenced_at", addr(reference.getFromAddress()));
                        row.put("function", function == null ? "null" : addr(function.getEntryPoint()));
                        stringRefs.add(row);
                        if (function != null) {
                            discovered.add(function);
                        }
                    }
                    cursor = found.add(1);
                }
            }
        }

        // ---- 0x21850 (and neighbourhood) accesses anywhere in the program
        InstructionIterator all = listing.getInstructions(true);
        Set<Long> seenFunctions = new LinkedHashSet<>();
        while (all.hasNext()) {
            Instruction insn = all.next();
            for (int opIndex = 0; opIndex < insn.getNumOperands(); opIndex++) {
                for (Object object : insn.getOpObjects(opIndex)) {
                    if (!(object instanceof Scalar)) {
                        continue;
                    }
                    long value = ((Scalar) object).getUnsignedValue();
                    if (value == NEIGHBOUR_OFFSET || (value >= 0x21800L && value <= 0x218a0L)) {
                        Function function = getFunctionContaining(insn.getAddress());
                        Map<String, String> row = new LinkedHashMap<>();
                        row.put("instruction", addr(insn.getAddress()) + " " + insn.toString());
                        row.put("offset", "0x" + Long.toUnsignedString(value, 16));
                        row.put("function", function == null ? "null" : addr(function.getEntryPoint()));
                        neighbourAccesses.add(row);
                        if (function != null) {
                            discovered.add(function);
                            seenFunctions.add(function.getEntryPoint().getOffset());
                        }
                    }
                }
            }
        }

        // ---- who references the dispatch globals
        for (long global : GLOBALS) {
            Address address = toAddr(global);
            ReferenceIterator iterator = refs.getReferencesTo(address);
            while (iterator.hasNext()) {
                Reference reference = iterator.next();
                Function function = getFunctionContaining(reference.getFromAddress());
                Map<String, String> row = new LinkedHashMap<>();
                row.put("global", addr(address));
                row.put("at", addr(reference.getFromAddress()) + " " + reference.getReferenceType().toString());
                row.put("function", function == null ? "null" : addr(function.getEntryPoint()));
                globalRefs.add(row);
                if (function != null) {
                    discovered.add(function);
                }
            }
        }

        // ---- decompile the newly discovered functions (bounded)
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Map<String, String> bodies = new LinkedHashMap<>();
        int decompiled = 0;
        for (Function function : discovered) {
            if (decompiled >= MAX_DECOMPILE) {
                break;
            }
            StringBuilder builder = new StringBuilder();
            builder.append("{\"entry\":\"").append(addr(function.getEntryPoint())).append("\"");
            builder.append(",\"instructions\":")
                   .append(listing.getInstructions(function.getBody(), true).hasNext() ? count(function) : 0);
            DecompileResults result = decompiler.decompileFunction(function, 25, monitor);
            if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                builder.append(",\"decompiled\":true,\"decompiled_c\":\"")
                       .append(esc(result.getDecompiledFunction().getC())).append("\"");
                decompiled++;
            } else {
                builder.append(",\"decompiled\":false");
            }
            builder.append("}");
            bodies.put(Long.toUnsignedString(function.getEntryPoint().getOffset(), 16), builder.toString());
        }
        decompiler.dispose();

        StringBuilder out = new StringBuilder();
        out.append("{\"strings\":[");
        boolean first = true;
        for (Map<String, String> row : stringRefs) {
            if (!first) { out.append(","); }
            first = false;
            out.append("{\"string\":\"").append(esc(row.get("string"))).append("\",\"address\":\"")
               .append(row.get("string_address")).append("\",\"at\":\"").append(row.get("referenced_at"))
               .append("\",\"function\":\"").append(row.get("function")).append("\"}");
        }
        out.append("],\"neighbour_0x21850\":[");
        first = true;
        for (Map<String, String> row : neighbourAccesses) {
            if (!first) { out.append(","); }
            first = false;
            out.append("{\"instruction\":\"").append(esc(row.get("instruction"))).append("\",\"offset\":\"")
               .append(row.get("offset")).append("\",\"function\":\"").append(row.get("function")).append("\"}");
        }
        out.append("],\"globals\":[");
        first = true;
        for (Map<String, String> row : globalRefs) {
            if (!first) { out.append(","); }
            first = false;
            out.append("{\"global\":\"").append(row.get("global")).append("\",\"at\":\"")
               .append(esc(row.get("at"))).append("\",\"function\":\"").append(row.get("function"))
               .append("\"}");
        }
        out.append("],\"functions\":{");
        first = true;
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
        println("LIVE26-DISPATCH-WRITTEN " + outPath + " strings=" + stringRefs.size()
                + " neighbour=" + neighbourAccesses.size() + " globals=" + globalRefs.size()
                + " functions=" + bodies.size());
    }

    private int count(Function function) {
        int total = 0;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            iterator.next();
            total++;
        }
        return total;
    }
}

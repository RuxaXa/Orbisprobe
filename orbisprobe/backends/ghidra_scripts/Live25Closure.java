// OrbisProbe LIVE2.5 whole-image CFG / type / indirect-call closure exporter.
// @category OrbisProbe
//
// Runs after a full auto-analysis of the FW13.52 kernel image and writes one JSON:
//   * recovered boundaries, basic blocks, p-code size, decompiled C for the target functions
//   * outgoing calls (direct + indirect) and incoming callers (the upward closure, depth-bounded)
//   * accesses to the object offsets 0x78 / 0x88 / 0xf0 / 0xf8 in every analysed function
// Nothing is guessed: every entry is an address or a count taken from the program database.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.scalar.Scalar;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Live25Closure extends GhidraScript {
    private static final long[] TARGETS = {
        Long.parseUnsignedLong("ffffffffd05ac8f0", 16),   // RC-001
        Long.parseUnsignedLong("ffffffffd05a7e20", 16),   // L1 caller A
        Long.parseUnsignedLong("ffffffffd05a8c32", 16),   // L1 caller B
        Long.parseUnsignedLong("ffffffffd057e7b0", 16)    // consumer
    };
    private static final long[] OBJECT_OFFSETS = { 0x78L, 0x88L, 0xf0L, 0xf8L };
    private static final int MAX_CALLERS = 120;
    private static final int MAX_DECOMPILE = 25;
    private static final int MAX_DEPTH = 6;

    private static String esc(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) { out.append(' '); } else { out.append(c); }
            }
        }
        return out.toString();
    }

    private static String addr(Address address) {
        return address == null ? "null" : "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "/tmp/live25-closure.json";
        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();
        BasicBlockModel blocks = new BasicBlockModel(currentProgram);
        Address min = currentProgram.getMinAddress();
        Address max = currentProgram.getMaxAddress();

        Map<String, String> functions = new LinkedHashMap<>();
        List<String> edges = new ArrayList<>();
        Set<Long> visited = new LinkedHashSet<>();
        ArrayDeque<long[]> queue = new ArrayDeque<>();     // {function entry, depth}
        for (long target : TARGETS) {
            queue.add(new long[] { target, 0 });
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int decompiled = 0;

        while (!queue.isEmpty() && visited.size() < MAX_CALLERS) {
            long[] item = queue.poll();
            Function function = getFunctionContaining(toAddr(item[0]));
            if (function == null) {
                functions.put(Long.toUnsignedString(item[0], 16),
                        "{\"recovered\":false,\"note\":\"no function contains this address\"}");
                continue;
            }
            long entry = function.getEntryPoint().getOffset();
            if (!visited.add(entry)) {
                continue;
            }
            int instructions = 0;
            int pcodeOps = 0;
            List<String> direct = new ArrayList<>();
            List<String> indirect = new ArrayList<>();
            List<String> fieldAccesses = new ArrayList<>();
            InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
            while (iterator.hasNext()) {
                Instruction insn = iterator.next();
                instructions++;
                PcodeOp[] ops = insn.getPcode();
                pcodeOps += ops == null ? 0 : ops.length;
                String mnemonic = insn.getMnemonicString();
                int flowType = insn.getFlowType().isCall() ? 1 : (insn.getFlowType().isJump() ? 2 : 0);
                if (flowType > 0) {
                    String target = "indirect";
                    if (insn.getNumOperands() > 0 && insn.getOpObjects(0).length == 1
                            && insn.getOpObjects(0)[0] instanceof Address) {
                        target = addr((Address) insn.getOpObjects(0)[0]);
                    }
                    String record = addr(insn.getAddress()) + " " + mnemonic + " "
                            + (insn.getNumOperands() > 0 ? insn.getDefaultOperandRepresentation(0) : "");
                    if ("indirect".equals(target)) {
                        indirect.add(esc(record));
                    } else {
                        direct.add(esc(record + " -> " + target));
                        if (flowType == 1) {
                            edges.add("{\"from\":\"" + addr(function.getEntryPoint()) + "\",\"callsite\":\""
                                    + addr(insn.getAddress()) + "\",\"to\":\"" + target + "\"}");
                        }
                    }
                }
                for (int opIndex = 0; opIndex < insn.getNumOperands(); opIndex++) {
                    for (Object object : insn.getOpObjects(opIndex)) {
                        if (object instanceof Scalar) {
                            long value = ((Scalar) object).getUnsignedValue();
                            for (long offset : OBJECT_OFFSETS) {
                                if (value == offset) {
                                    fieldAccesses.add(esc("0x" + Long.toUnsignedString(offset, 16) + " @ "
                                            + addr(insn.getAddress()) + " " + mnemonic + " "
                                            + insn.toString()));
                                }
                            }
                        }
                    }
                }
            }
            int blockCount = 0;
            CodeBlockIterator blockIterator = blocks.getCodeBlocksContaining(function.getBody(), monitor);
            while (blockIterator.hasNext()) {
                CodeBlock block = blockIterator.next();
                blockCount++;
                if (blockCount > 4000) {
                    break;
                }
            }
            List<String> callerRefs = new ArrayList<>();
            ReferenceIterator incoming = refs.getReferencesTo(function.getEntryPoint());
            while (incoming.hasNext()) {
                Reference reference = incoming.next();
                if (!reference.getReferenceType().isCall()) {
                    continue;
                }
                Function caller = getFunctionContaining(reference.getFromAddress());
                String from = caller == null ? "null" : addr(caller.getEntryPoint());
                callerRefs.add(esc(from + " @ " + addr(reference.getFromAddress())));
                if (caller != null && item[1] < MAX_DEPTH) {
                    queue.add(new long[] { caller.getEntryPoint().getOffset(), item[1] + 1 });
                }
            }
            String decompiledC = "";
            boolean decompilerOk = false;
            if (decompiled < MAX_DECOMPILE) {
                DecompileResults result = decompiler.decompileFunction(function, 20, monitor);
                decompilerOk = result != null && result.decompileCompleted();
                if (decompilerOk && result.getDecompiledFunction() != null) {
                    decompiledC = result.getDecompiledFunction().getC();
                    decompiled++;
                }
            }
            StringBuilder builder = new StringBuilder();
            builder.append("{\"recovered\":true");
            builder.append(",\"entry\":\"").append(addr(function.getEntryPoint())).append("\"");
            builder.append(",\"end\":\"").append(addr(function.getBody().getMaxAddress())).append("\"");
            builder.append(",\"name\":\"").append(esc(function.getName())).append("\"");
            builder.append(",\"signature\":\"").append(esc(function.getSignature().getPrototypeString()))
                   .append("\"");
            builder.append(",\"instructions\":").append(instructions);
            builder.append(",\"pcode_ops\":").append(pcodeOps);
            builder.append(",\"basic_blocks\":").append(blockCount);
            builder.append(",\"callers\":[").append(String.join(",", quote(callerRefs))).append("]");
            builder.append(",\"direct_calls\":[").append(String.join(",", quote(direct))).append("]");
            builder.append(",\"indirect_calls\":[").append(String.join(",", quote(indirect))).append("]");
            builder.append(",\"object_field_accesses\":[").append(String.join(",", quote(fieldAccesses)))
                   .append("]");
            builder.append(",\"decompiled\":").append(decompilerOk);
            builder.append(",\"decompiled_c\":\"").append(esc(decompiledC)).append("\"");
            builder.append("}");
            functions.put(Long.toUnsignedString(entry, 16), builder.toString());
        }
        decompiler.dispose();

        StringBuilder out = new StringBuilder();
        out.append("{\"file\":\"").append(esc(currentProgram.getExecutablePath())).append("\"");
        out.append(",\"image_base\":\"").append(addr(min)).append("\"");
        out.append(",\"image_max\":\"").append(addr(max)).append("\"");
        out.append(",\"function_count\":").append(currentProgram.getFunctionManager().getFunctionCount());
        out.append(",\"analysed_functions\":").append(functions.size());
        out.append(",\"decompiled_functions\":").append(decompiled);
        out.append(",\"edges\":[").append(String.join(",", edges)).append("]");
        out.append(",\"functions\":{");
        boolean first = true;
        for (Map.Entry<String, String> entry : functions.entrySet()) {
            if (!first) {
                out.append(",");
            }
            first = false;
            out.append("\"").append(entry.getKey()).append("\":").append(entry.getValue());
        }
        out.append("}}");

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8))) {
            writer.write(out.toString());
        }
        println("LIVE25-EXPORT-WRITTEN " + outPath + " functions=" + functions.size());
    }

    private static List<String> quote(List<String> values) {
        List<String> out = new ArrayList<>();
        for (String value : values) {
            out.add("\"" + value + "\"");
        }
        return out;
    }
}

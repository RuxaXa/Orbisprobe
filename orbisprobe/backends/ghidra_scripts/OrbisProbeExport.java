// OrbisProbe Ghidra headless evidence exporter.
// @category OrbisProbe

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class OrbisProbeExport extends GhidraScript {
    private int maximumItems;

    private static String escape(String value) {
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
                    if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
                    else out.append(c);
            }
        }
        return out.toString();
    }

    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof String) return "\"" + escape((String)value) + "\"";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map) {
            StringBuilder out = new StringBuilder("{");
            boolean first = true;
            for (Object rawEntry : ((Map<?, ?>)value).entrySet()) {
                Map.Entry<?, ?> entry = (Map.Entry<?, ?>)rawEntry;
                if (!first) out.append(',');
                first = false;
                out.append(json(String.valueOf(entry.getKey()))).append(':').append(json(entry.getValue()));
            }
            return out.append('}').toString();
        }
        if (value instanceof Collection) {
            StringBuilder out = new StringBuilder("[");
            boolean first = true;
            for (Object item : (Collection<?>)value) {
                if (!first) out.append(',');
                first = false;
                out.append(json(item));
            }
            return out.append(']').toString();
        }
        return json(String.valueOf(value));
    }

    private static String addr(Address address) {
        return address == null ? null : "0x" + address.toString(false, false);
    }

    private static Map<String, Object> varnode(Varnode value) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (value == null) return out;
        out.put("address", addr(value.getAddress()));
        out.put("size", value.getSize());
        out.put("constant", value.isConstant());
        out.put("register", value.isRegister());
        out.put("unique", value.isUnique());
        out.put("offset", "0x" + Long.toUnsignedString(value.getOffset(), 16));
        return out;
    }

    private Address parseRequestedAddress(String text) throws Exception {
        String clean = text.startsWith("0x") ? text.substring(2) : text;
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(clean);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) throw new IllegalArgumentException("expected: output function max-items");
        File output = new File(args[0]).getCanonicalFile();
        Address requested = parseRequestedAddress(args[1]);
        maximumItems = Math.max(1, Math.min(Integer.parseInt(args[2]), 100000));

        Function function = getFunctionAt(requested);
        if (function == null) function = getFunctionContaining(requested);
        if (function == null) {
            disassemble(requested);
            function = createFunction(requested, null);
        }
        if (function == null) throw new IllegalStateException("unable to recover function at " + requested);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schema", "orbisprobe-ghidra-pcode-v1");
        root.put("program", currentProgram.getName());
        root.put("language", currentProgram.getLanguageID().toString());
        root.put("image_base", addr(currentProgram.getImageBase()));

        Map<String, Object> functionData = new LinkedHashMap<>();
        functionData.put("name", function.getName());
        functionData.put("entry", addr(function.getEntryPoint()));
        functionData.put("size", function.getBody().getNumAddresses());
        root.put("function", functionData);

        List<Object> parameters = new ArrayList<>();
        for (Parameter parameter : function.getParameters()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", parameter.getName());
            item.put("ordinal", parameter.getOrdinal());
            item.put("storage", parameter.getVariableStorage().toString());
            item.put("data_type", parameter.getDataType().getDisplayName());
            parameters.add(item);
        }
        root.put("parameters", parameters);

        List<Object> stackVariables = new ArrayList<>();
        for (Variable variable : function.getAllVariables()) {
            if (!variable.isStackVariable()) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", variable.getName());
            item.put("storage", variable.getVariableStorage().toString());
            item.put("data_type", variable.getDataType().getDisplayName());
            stackVariables.add(item);
        }
        root.put("stack_variables", stackVariables);

        List<Object> instructions = new ArrayList<>();
        List<Object> pcode = new ArrayList<>();
        List<Object> definitions = new ArrayList<>();
        List<Object> consumers = new ArrayList<>();
        List<Object> memoryAccesses = new ArrayList<>();
        List<Object> calls = new ArrayList<>();
        List<Object> blocks = new ArrayList<>();
        int count = 0;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext() && count < maximumItems) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            Map<String, Object> ins = new LinkedHashMap<>();
            ins.put("address", addr(instruction.getAddress()));
            ins.put("mnemonic", instruction.getMnemonicString());
            ins.put("text", instruction.toString());
            ins.put("length", instruction.getLength());
            instructions.add(ins);

            if (count == 0 || instruction.getFlowType().isJump()) {
                Map<String, Object> block = new LinkedHashMap<>();
                block.put("address", addr(instruction.getAddress()));
                block.put("flow_type", instruction.getFlowType().toString());
                blocks.add(block);
            }
            if (instruction.getFlowType().isCall()) {
                for (Address target : instruction.getFlows()) {
                    Map<String, Object> call = new LinkedHashMap<>();
                    call.put("address", addr(instruction.getAddress()));
                    call.put("target", addr(target));
                    calls.add(call);
                }
            }

            for (PcodeOp op : instruction.getPcode()) {
                if (pcode.size() >= maximumItems) break;
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("address", addr(instruction.getAddress()));
                item.put("opcode", op.getMnemonic());
                item.put("output", varnode(op.getOutput()));
                List<Object> inputs = new ArrayList<>();
                for (int i = 0; i < op.getNumInputs(); i++) inputs.add(varnode(op.getInput(i)));
                item.put("inputs", inputs);
                pcode.add(item);
                if (op.getOutput() != null) definitions.add(item);
                if (op.getNumInputs() > 0) consumers.add(item);
                if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) memoryAccesses.add(item);
            }
            count++;
        }
        root.put("instructions", instructions);
        root.put("pcode", pcode);
        root.put("definitions", definitions);
        root.put("consumers", consumers);
        root.put("memory_accesses", memoryAccesses);
        root.put("calls", calls);
        root.put("blocks", blocks);

        List<Object> callers = new ArrayList<>();
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (refs.hasNext() && callers.size() < maximumItems) {
            Reference ref = refs.next();
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("from", addr(ref.getFromAddress()));
            item.put("type", ref.getReferenceType().toString());
            callers.add(item);
        }
        root.put("xrefs", callers);

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            DecompileResults decompiled = decompiler.decompileFunction(function, 30, monitor);
            if (decompiled != null && decompiled.decompileCompleted() &&
                    decompiled.getDecompiledFunction() != null) {
                root.put("decompiler_c", decompiled.getDecompiledFunction().getC());
            } else {
                root.put("decompiler_c", null);
            }
        } finally {
            decompiler.dispose();
        }
        root.put("partial", count >= maximumItems || pcode.size() >= maximumItems);

        File parent = output.getParentFile();
        if (parent == null || !parent.isDirectory()) throw new IllegalArgumentException("output parent missing");
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            writer.write(json(root));
            writer.newLine();
        }
    }
}

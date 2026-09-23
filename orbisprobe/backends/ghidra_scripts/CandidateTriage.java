// OrbisProbe campaign v2 — structured candidate triage.
// Emits per candidate function: CFG-confirmed flag, instruction count, DIRECT call targets per callsite
// (from the listing reference model, NOT from decompiled-C regexes), indirect-call callsites, and the
// decompiled C. Then decompiles the collected callees so consumer semantics can be classified offline.
// @category OrbisProbe

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CandidateTriage extends GhidraScript {
    private static final int MAX_CALLEES = 600;

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

    private static String hex(Address a) {
        return a == null ? "" : "0x" + Long.toUnsignedString(a.getOffset(), 16);
    }

    private static String insnText(Instruction insn) {
        StringBuilder sb = new StringBuilder(insn.getMnemonicString());
        int n = insn.getNumOperands();
        if (n > 0) sb.append(' ');
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            sb.append(insn.getDefaultOperandRepresentation(i));
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String listPath = getScriptArgs()[0];
        String outPath = getScriptArgs()[1];
        List<Long> entries = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(listPath), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) entries.add(Long.parseUnsignedLong(line, 16));
            }
        }
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        StringBuilder sb = new StringBuilder("{\"schema\":\"orbisprobe-candidate-triage-v1\",\"candidates\":{");
        Set<Function> callees = new LinkedHashSet<>();
        boolean first = true;
        for (long entry : entries) {
            Function f = getFunctionContaining(toAddr(entry));
            if (f == null) {
                if (!first) sb.append(",");
                first = false;
                sb.append("\"").append(Long.toUnsignedString(entry, 16)).append("\":{\"cfg_confirmed\":false}");
                continue;
            }
            Map<String, String> calls = new LinkedHashMap<>();
            List<String> indirect = new ArrayList<>();
            int insns = 0;
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (ii.hasNext()) {
                Instruction insn = ii.next();
                insns++;
                FlowType ft = insn.getFlowType();
                if (!ft.isCall()) continue;
                Address[] flows = insn.getFlows();
                String site = hex(insn.getAddress());
                if (flows != null && flows.length == 1) {
                    calls.put(site, hex(flows[0]));
                    Function callee = getFunctionContaining(flows[0]);
                    if (callee != null) callees.add(callee);
                } else {
                    indirect.add(site);
                }
            }
            DecompileResults res = dec.decompileFunction(f, 30, monitor);
            String c = (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null)
                    ? res.getDecompiledFunction().getC() : "";
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(Long.toUnsignedString(entry, 16)).append("\":{\"cfg_confirmed\":true")
              .append(",\"entry\":\"").append(hex(f.getEntryPoint())).append("\"")
              .append(",\"name\":\"").append(esc(f.getName())).append("\"")
              .append(",\"instructions\":").append(insns)
              .append(",\"direct_calls\":{");
            boolean f2 = true;
            for (Map.Entry<String, String> e : calls.entrySet()) {
                if (!f2) sb.append(",");
                f2 = false;
                sb.append("\"").append(e.getKey()).append("\":\"").append(e.getValue()).append("\"");
            }
            sb.append("},\"indirect_call_sites\":[");
            for (int i = 0; i < indirect.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\"").append(indirect.get(i)).append("\"");
            }
            sb.append("],\"c\":\"").append(esc(c)).append("\"}");
        }
        sb.append("},\"callees\":{");
        boolean f3 = true;
        int emitted = 0;
        for (Function f : callees) {
            if (emitted >= MAX_CALLEES) break;
            DecompileResults res = dec.decompileFunction(f, 30, monitor);
            if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) continue;
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            int insns = 0;
            while (ii.hasNext()) { ii.next(); insns++; }
            if (!f3) sb.append(",");
            f3 = false;
            emitted++;
            sb.append("\"").append(Long.toUnsignedString(f.getEntryPoint().getOffset(), 16))
              .append("\":{\"entry\":\"").append(hex(f.getEntryPoint())).append("\",\"instructions\":").append(insns)
              .append(",\"c\":\"").append(esc(res.getDecompiledFunction().getC())).append("\"}");
        }
        sb.append("}}");
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(outPath), StandardCharsets.UTF_8))) { w.write(sb.toString()); }
        println("TRIAGE-WRITTEN " + outPath + " candidates=" + entries.size() + " callees=" + emitted);
    }
}

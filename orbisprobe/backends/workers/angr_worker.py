from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, allow_nan=False))
    sys.stdout.write("\n")


def project_for(request: dict):
    import angr
    import archinfo
    import cle

    binary = Path(request["binary"])
    base = int(request["base"])
    function = int(request.get("function", base))
    architecture = request.get("architecture", "x86_64")
    if architecture != "x86_64":
        raise ValueError(f"unsupported architecture: {architecture}")
    stream = binary.open("rb")
    blob = cle.Blob(
        str(binary),
        stream,
        arch=archinfo.ArchAMD64(),
        base_addr=base,
        entry_point=function,
    )
    return angr.Project(blob, auto_load_libs=False)


def recover_cfg(request: dict) -> dict:
    project = project_for(request)
    function = int(request["function"])
    function_end = int(request.get("function_end", project.loader.main_object.max_addr + 1))
    cfg = project.analyses.CFGFast(
        function_starts=[function],
        start_at_entry=False,
        regions=[(function, function_end)],
        normalize=True,
        resolve_indirect_jumps=False,
        data_references=True,
        force_complete_scan=False,
    )
    recovered = cfg.kb.functions.get(function)
    if recovered is None:
        return {"function": function, "blocks": [], "calls": [], "complete": False}
    blocks = []
    calls = []
    for block in sorted(recovered.blocks, key=lambda item: item.addr):
        if block.addr >= function_end:
            continue
        blocks.append({"address": block.addr, "size": block.size})
        for instruction in block.capstone.insns:
            if instruction.mnemonic.startswith("call"):
                calls.append({"address": instruction.address, "op_str": instruction.op_str})
    return {
        "function": function,
        "function_name": recovered.name,
        "blocks": blocks,
        "calls": calls,
        "complete": bool(blocks),
    }


def initial_state(project, request: dict):
    import claripy

    start = int(request.get("from", request["function"]))
    state = project.factory.blank_state(addr=start)
    state.regs.rsp = 0x7FFF0000
    source = request.get("source") or {}
    if source:
        register = source.get("register")
        bits = int(source.get("symbolic_bits", 64))
        if register:
            setattr(state.regs, register, claripy.BVS(f"source_{register}", bits))
    for register in request.get("symbolic_registers", []):
        setattr(state.regs, register, claripy.BVS(f"source_{register}", 64))
    for register, value in request.get("initial_registers", {}).items():
        setattr(state.regs, register, int(value))
    return state


def bounded_explore(request: dict, limits: dict, target: int) -> tuple[list, dict, bool]:
    project = project_for(request)
    target = int(target)
    function_start = int(request["function"])
    function_end = int(request.get("function_end", project.loader.main_object.max_addr + 1))
    state = initial_state(project, request)
    active = [state]
    found = []
    steps = 0
    peak_states = 1
    ceiling = int(limits["state_ceiling"])
    step_ceiling = int(limits["maximum_steps"])
    incomplete = False
    while active and steps < step_ceiling and len(found) < ceiling:
        matching = [item for item in active if item.addr == target]
        if matching:
            found.extend(matching)
            active = [item for item in active if item.addr != target]
            if len(found) >= ceiling:
                incomplete = True
                break
        if not active:
            break
        successors = []
        for item in active:
            successors.extend(project.factory.successors(item, num_inst=1).flat_successors)
        active = [
            item
            for item in successors
            if item.addr == target or function_start <= item.addr < function_end
        ]
        steps += 1
        peak_states = max(peak_states, len(active))
        if len(active) > ceiling:
            active = active[:ceiling]
            incomplete = True
    if steps >= step_ceiling and active:
        incomplete = True
    return found, {"steps": steps, "peak_states": peak_states}, incomplete


def trace_value(request: dict, limits: dict) -> tuple[str, dict, list, list]:
    target = int(request["consumer"])
    found, metrics, incomplete = bounded_explore(request, limits, target)
    observe = request.get("observe") or request.get("source") or {}
    register = observe.get("register")
    maximum = min(int(observe.get("max_values", 32)), 256)
    values: set[int] = set()
    constraints: list[str] = []
    lifetime_values: set[bool] = set()
    source_register = (request.get("source") or {}).get("register")
    for state in found:
        expression = getattr(state.regs, register)
        values.update(int(item) for item in state.solver.eval_upto(expression, maximum))
        constraints.extend(str(item) for item in state.solver.constraints)
        if source_register:
            lifetime_values.add(
                any(name.startswith(f"source_{source_register}") for name in expression.variables)
            )
    data = {
        "consumer_reachable": bool(found),
        "consumer": target,
        "register": register,
        "value_domain": sorted(values),
        "constraints": sorted(set(constraints)),
        "exploration_metrics": metrics,
    }
    evidence = []
    if found:
        evidence.append(
            {
                "kind": "value_domain",
                "subject": f"{register}@0x{target:x}",
                "value": sorted(values),
                "address": target,
                "confidence": "SUPPORTED",
                "provenance": {"source_class": "symbolic", "engine": "angr-claripy"},
            }
        )
        if source_register and len(lifetime_values) == 1:
            evidence.append(
                {
                    "kind": "register_lifetime",
                    "subject": f"{register}@0x{target:x}",
                    "value": next(iter(lifetime_values)),
                    "address": target,
                    "confidence": "SUPPORTED",
                    "provenance": {
                        "source_class": "symbolic",
                        "engine": "angr-claripy",
                        "source_register": source_register,
                    },
                }
            )
    status = "ANALYSIS_INCOMPLETE" if incomplete else "COMPLETED"
    unknowns = ["path/state ceiling reached"] if incomplete else []
    return status, data, evidence, unknowns


def branch_constraints(request: dict, limits: dict) -> tuple[str, dict, list, list]:
    target = int(request["to"])
    found, metrics, incomplete = bounded_explore(request, limits, target)
    constraints = sorted({str(item) for state in found for item in state.solver.constraints})
    status = "ANALYSIS_INCOMPLETE" if incomplete else "COMPLETED"
    return status, {"reachable": bool(found), "target": target, "constraints": constraints, **metrics}, [], (
        ["path/state ceiling reached"] if incomplete else []
    )


def vex_facts(request: dict, maximum_graph_size: int = 100000) -> dict:
    project = project_for(request)
    function = int(request["function"])
    end = int(request.get("function_end", function + 0x1000))
    cfg = recover_cfg(request)
    definitions = []
    consumers = []
    accesses = []
    for item in cfg["blocks"]:
        block = project.factory.block(item["address"], size=min(item["size"], end - item["address"]))
        for statement in block.vex.statements:
            tag = getattr(statement, "tag", type(statement).__name__)
            text = str(statement)
            record = {"block": block.addr, "tag": tag, "text": text}
            if tag == "Ist_Put":
                definitions.append(record)
            if "Get(" in text or tag in {"Ist_LoadG", "Ist_Store", "Ist_StoreG"}:
                consumers.append(record)
            if "Load" in text or "Store" in text or tag in {"Ist_LoadG", "Ist_Store", "Ist_StoreG"}:
                accesses.append(record)
    reaching_definitions = []
    dependency_edges = []
    try:
        cfg_analysis = project.analyses.CFGFast(
            function_starts=[function],
            start_at_entry=False,
            regions=[(function, end)],
            normalize=True,
            resolve_indirect_jumps=False,
            data_references=True,
            force_complete_scan=False,
        )
        recovered = cfg_analysis.kb.functions.get(function)
        if recovered is not None:
            rda = project.analyses.ReachingDefinitions(subject=recovered, observe_all=True)
            for definition in list(rda.all_definitions)[:maximum_graph_size]:
                reaching_definitions.append(
                    {
                        "atom": str(definition.atom),
                        "code_location": str(definition.codeloc),
                        "instruction": getattr(definition.codeloc, "ins_addr", None),
                    }
                )
            for source, target in list(rda.dep_graph.graph.edges())[:maximum_graph_size]:
                dependency_edges.append({"source": str(source), "target": str(target)})
    except Exception as exc:  # noqa: BLE001 - RDA failure leaves lower-level facts available
        reaching_definitions.append({"error": f"{type(exc).__name__}: {exc}"})
    return {
        "definitions": definitions,
        "consumers": consumers,
        "memory_accesses": accesses,
        "reaching_definitions": reaching_definitions,
        "dependency_edges": dependency_edges,
        "cfg": cfg,
    }


def main() -> int:
    started = time.monotonic()
    try:
        import angr

        raw = json.loads(sys.stdin.read())
        operation = raw["operation"]
        request = raw.get("request", {})
        limits = raw.get("limits", {})
        if operation == "version":
            emit({"status": "COMPLETED", "version": angr.__version__, "data": {"available": True}})
            return 0
        if operation == "recover_cfg":
            data = recover_cfg(request)
            status = "COMPLETED" if data.get("complete") else "ANALYSIS_INCOMPLETE"
            evidence = []
            unknowns = [] if data.get("complete") else ["CFGFast did not recover the requested function"]
        elif operation == "analyze_function":
            data = vex_facts(request, int(limits["maximum_graph_size"]))
            status = "COMPLETED" if data.get("cfg", {}).get("complete") else "ANALYSIS_INCOMPLETE"
            evidence = []
            unknowns = [] if status == "COMPLETED" else ["CFGFast did not recover the requested function"]
        elif operation == "trace_value":
            status, data, evidence, unknowns = trace_value(request, limits)
        elif operation == "evaluate_branch_constraints":
            status, data, evidence, unknowns = branch_constraints(request, limits)
        elif operation == "find_definitions":
            facts = vex_facts(request, int(limits["maximum_graph_size"]))
            data = {
                "definitions": facts["definitions"],
                "reaching_definitions": facts["reaching_definitions"],
                "dependency_edges": facts["dependency_edges"],
            }
            status, evidence, unknowns = "COMPLETED", [], []
        elif operation == "find_consumers":
            data = {"consumers": vex_facts(request, int(limits["maximum_graph_size"]))["consumers"]}
            status, evidence, unknowns = "COMPLETED", [], []
        elif operation == "analyze_memory_access":
            data = {
                "memory_accesses": vex_facts(
                    request, int(limits["maximum_graph_size"])
                )["memory_accesses"]
            }
            status, evidence, unknowns = "COMPLETED", [], []
        elif operation == "resolve_call_arguments":
            data = {"arguments": [], "complete": False}
            status, evidence, unknowns = "ANALYSIS_INCOMPLETE", [], ["call argument recovery not closed"]
        else:
            raise ValueError(f"unsupported operation: {operation}")
        emit(
            {
                "status": status,
                "version": angr.__version__,
                "data": data,
                "evidence": evidence,
                "unknowns": unknowns,
                "metrics": {"elapsed_seconds": round(time.monotonic() - started, 6)},
            }
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - worker returns structured failure
        emit(
            {
                "status": "ERROR",
                "version": "unknown",
                "data": {},
                "evidence": [],
                "unknowns": [],
                "errors": [f"{type(exc).__name__}: {exc}"],
                "metrics": {"elapsed_seconds": round(time.monotonic() - started, 6)},
            }
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""OrbisProbe Live — TRACE-Client mit strikter Request/Antwort-Korrelation.

Behebt 12Q-Finding F5: eine verspaetete Mutationsantwort (z. B. op=restore) darf NIE einer
neuen Operation zugeordnet werden. Und 12Q-Finding F4: die Post-Test-Reihenfolge ist fest —
Aufraeumpruefungen (Restprozesse, Ports) erst NACH dem Bridge-Stop.

Regeln:
  * Jede Anfrage traegt eine monotone request_id (`req=<n>`); der Payload echot sie.
  * Eine Antwort wird nur akzeptiert, wenn req UND Operation passen.
  * Fremde/verspaetete Antworten werden geloggt (`late_responses`) und verworfen.
  * Mutationen werden als dispatched markiert: ein Timeout nach dem Absetzen ist kein Beweis,
    dass nichts geschrieben wurde -> Zustand muss per Readback geprueft werden.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

TRACE_RE = re.compile(r"^(OK|ERR) TRACE (.*)$")


class TraceError(RuntimeError):
    def __init__(self, msg: str, dispatched: bool = False):
        super().__init__(msg)
        self.dispatched = dispatched


@dataclass
class TraceClient:
    send_line: Callable                       # (str) -> None
    recv_line: Callable                       # (timeout) -> str
    log: Callable = print
    seq: int = 0
    late_responses: list = field(default_factory=list)
    accepted: list = field(default_factory=list)

    # ---------------------------------------------------------------- Wire
    @staticmethod
    def parse(line: str) -> dict:
        m = TRACE_RE.match(line.strip())
        if not m:
            raise TraceError(f"keine TRACE-Antwort: {line!r}")
        d: dict = {"status": m.group(1)}
        for tok in m.group(2).split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                d[k] = v
        return d

    def _request_line(self, op: str | None, stage: int | None) -> tuple[int, str]:
        self.seq += 1
        parts = ["TRACE", f"req={self.seq}"]
        if op:
            parts.append(f"op={op}")
        if stage is not None:
            parts.append(f"stage={stage}")           # als Dezimalzahl, Payload parst Ziffern
        return self.seq, " ".join(parts)

    # ---------------------------------------------------------------- Korrelation
    def request(self, op: str | None = None, stage: int | None = None, mutation: bool = False,
                rounds: int = 8):
        """Sendet eine TRACE-Anfrage und liefert NUR die korrelierte Antwort."""
        rid, line = self._request_line(op, stage)
        dispatched = False
        try:
            self.send_line(line)
            dispatched = True
        except Exception as exc:
            raise TraceError(f"req={rid} nicht abgesetzt: {exc}") from exc
        for _ in range(rounds):
            try:
                raw = self.recv_line(timeout=8)
            except Exception as exc:
                raise TraceError(f"req={rid} timeout nach dispatch={dispatched}: {exc}",
                                 dispatched=dispatched if mutation else False) from exc
            try:
                d = self.parse(raw)
            except TraceError:
                self.late_responses.append({"req": rid, "raw": raw[:200],
                                            "grund": "kein TRACE-Frame"})
                continue
            got = str(d.get("req", ""))
            got_op = d.get("op", "")
            if got != str(rid):
                self.late_responses.append({"req": rid, "antwort_req": got, "op": got_op,
                                            "grund": "req-ID passt nicht (late response)"})
                self.log(f"    late response verworfen: erwartet req={rid}, kam req={got} "
                         f"op={got_op}")
                continue
            if op and got_op and got_op != op:
                self.late_responses.append({"req": rid, "antwort_req": got, "op": got_op,
                                            "grund": f"Operation passt nicht (erwartet {op})"})
                self.log(f"    Antwort mit falscher Operation verworfen: {got_op} != {op}")
                continue
            self.accepted.append({"req": rid, "op": op or "status", "antwort": d})
            return d
        raise TraceError(f"req={rid} keine korrelierte Antwort in {rounds} Runden",
                         dispatched=dispatched if mutation else False)


# ------------------------------------------------------------------ Health-Reihenfolge (F4/I)
HEALTH_ORDER = [
    "1_trace_op_completed",
    "2_restore_verified",
    "3_bridge_stopped",
    "4_leftover_processes",
    "5_ports",
    "6_kbase_A3_aperture",
    "7_rb1_activity",
    "8_icmp",
]

#: Schritte, die zwingend NACH dem Bridge-Stop laufen muessen.
AFTER_BRIDGE_STOP = {"4_leftover_processes", "5_ports"}

#: Schritte, deren Werte nur ueber den offenen Kanal zu LESEN sind. Sie werden waehrend der
#: offenen Sitzung erhoben (Schritt 2) und an ihrer Position 6/7 berichtet und bewertet — so
#: bleibt die geforderte Reihenfolge gewahrt, ohne dass nach dem Stop ein Kanal gebraucht wird.
CHANNEL_VALUES = ("6_kbase_A3_aperture", "7_rb1_activity")


def health_sequence(probe: dict) -> list[dict]:
    """Fuehrt die feste Reihenfolge aus. probe = {name: callable}."""
    out = []
    for step in HEALTH_ORDER:
        if step not in probe:
            raise TraceError(f"Health-Schritt fehlt: {step}")
        res = probe[step]()
        out.append({"schritt": step, "ergebnis": res})
    return out


def check_health_order(executed: list[dict]) -> dict:
    names = [s["schritt"] for s in executed]
    idx = {n: i for i, n in enumerate(names)}
    checks = {
        "reihenfolge_vollstaendig": names == HEALTH_ORDER,
        "kein_restprozess_check_vor_bridge_stop":
            all(idx[s] > idx["3_bridge_stopped"] for s in AFTER_BRIDGE_STOP if s in idx),
        "icmp_zuletzt": names and names[-1] == "8_icmp",
        "kanalwerte_ohne_nachzaehlige_aktion":
            all("aus_sitzung" in str(next((x for x in executed if x["schritt"] == s), {}))
                for s in CHANNEL_VALUES) if all(
                    any(x["schritt"] == s for x in executed) for s in CHANNEL_VALUES) else False,
    }
    checks["bestanden"] = all(checks.values())
    return {"checks": checks, "reihenfolge": names,
            "hinweis": "Materiale Regeln: keine Prozess-/Portpruefung vor dem Bridge-Stop, ICMP "
                       "zuletzt. Die Kanalwerte fuer Schritt 6/7 stammen aus der offenen Sitzung "
                       "(vor dem Stop) und werden an ihrer Position berichtet."}

from pathlib import Path

from orbisprobe.evidence import EvidenceLog
from orbisprobe.policy import Policy
from orbisprobe.runner import Runner
from orbisprobe.schema import Experiment, RiskClass, Step, experiment_sha256
from orbisprobe.targets.offline import OfflineTarget


def test_offline_hash(tmp_path: Path):
    f = tmp_path / "a.bin"; f.write_bytes(b"abc")
    e = Experiment("h","h","h",RiskClass.OFFLINE, steps=[Step("hash_file", {"path":str(f)})])
    r = Runner(OfflineTarget(), Policy(max_risk=RiskClass.OFFLINE), EvidenceLog(tmp_path/"e.jsonl")).run(
        e, expected_plan_sha256=experiment_sha256(e)
    )
    assert r["ok"] and r["results"][0]["length"] == 3

from orbisprobe.policy import Policy
from orbisprobe.schema import Experiment, RiskClass, Step


def test_persistent_blocked():
    e = Experiment("x","x","x",RiskClass.PERSISTENT)
    assert Policy(max_risk=RiskClass.PERSISTENT).validate(e)

def test_kernel_write_requires_restore():
    e = Experiment("x","x","x",RiskClass.REVERSIBLE_KERNEL_RAM, steps=[Step("write_memory", {"data_hex":"00"})])
    errs = Policy(max_risk=RiskClass.REVERSIBLE_KERNEL_RAM).validate(e)
    assert any("restore" in x for x in errs)

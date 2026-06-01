from pathlib import Path
from eadf.evaluation.contract_stats import analyze_contract

REPO = Path(__file__).resolve().parents[2]


def test_analyze_contract_on_real_file():
    cs = analyze_contract(REPO / "src" / "vulnerable" / "VulnerableLogicV1.sol")
    assert cs.loc > 0
    assert cs.n_state_vars >= 2      # value, owner
    assert cs.n_slots >= 2
    assert cs.packed in (True, False)
    assert cs.has_dynamic in (True, False)

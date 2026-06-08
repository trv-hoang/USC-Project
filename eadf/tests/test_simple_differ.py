from pathlib import Path
from eadf.module2_ast_diff.slither_ast import build_ast, extract_state_variables
from eadf.module2_ast_diff.simple_differ import SimpleASTDiffer

ROOT = Path(__file__).parent / "fixtures" / "diff_pair"


def _diff(v1, v2):
    ast_v1 = build_ast(ROOT / v1)
    ast_v2 = build_ast(ROOT / v2)
    return SimpleASTDiffer().diff(
        ast_v1,
        ast_v2,
        v1_state_vars=extract_state_variables(ast_v1),
        v2_state_vars=extract_state_variables(ast_v2),
    )


def test_insert_state_var():
    d = _diff("V1.sol", "V2_insert.sol")
    inserts = [c for c in d.changes if c.op == "INSERT"]
    assert any(c.node_name == "newVar" for c in inserts)


def test_delete_state_var():
    d = _diff("V1.sol", "V2_delete.sol")
    deletes = [c for c in d.changes if c.op == "DELETE"]
    assert any(c.node_name == "b" for c in deletes)


def test_no_changes_when_identical():
    d = _diff("V1.sol", "V1.sol")
    assert d.changes == []
    assert d.summary == {"insert": 0, "delete": 0, "update": 0}


def test_summary_counts_correct():
    d = _diff("V1.sol", "V2_insert.sol")
    assert d.summary["insert"] >= 1
    assert d.summary["delete"] == 0

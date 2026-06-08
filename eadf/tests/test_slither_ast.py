from pathlib import Path
from eadf.module2_ast_diff.slither_ast import build_ast, extract_state_variables

FIXTURE = Path(__file__).parent / "fixtures" / "min_contract" / "MinV1.sol"

def test_build_ast_returns_target_contract():
    ast = build_ast(FIXTURE)
    assert ast.contract_name == "MinV1"

def test_extract_state_variables_in_declared_order():
    ast = build_ast(FIXTURE)
    vars_ = extract_state_variables(ast)
    names = [v.name for v in vars_]
    assert names == ["value", "owner", "flag"]
    assert vars_[0].type == "uint256"
    assert vars_[1].type == "address"
    assert vars_[2].type == "bool"

def test_picks_contract_by_filename_stem_not_last():
    # Smoke test against a real production contract that imports many OZ files.
    # Without the stem-based selection rule, contracts[-1] picks an OZ contract.
    repo = Path(__file__).resolve().parents[2]
    ast = build_ast(repo / "src" / "secure" / "SecureLogicV1.sol")
    assert ast.contract_name == "SecureLogicV1"

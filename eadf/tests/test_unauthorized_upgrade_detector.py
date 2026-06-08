from pathlib import Path
from eadf.module2_ast_diff.slither_ast import build_ast
from eadf.module3_vuln_detector.unauthorized_upgrade_detector import detect_missing_upgrade_authorization

ROOT = Path(__file__).parent / "fixtures" / "unauthorized"

def test_flags_vulnerable():
    ast = build_ast(ROOT / "Vulnerable.sol")
    findings = detect_missing_upgrade_authorization(ast, source_file="Vulnerable.sol")
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_id == "missing-upgrade-authorization"
    assert f.severity == "High"
    assert f.location.function_name == "_authorizeUpgrade"

def test_no_finding_on_secure():
    ast = build_ast(ROOT / "Secure.sol")
    assert detect_missing_upgrade_authorization(ast, source_file="Secure.sol") == []

def test_no_finding_when_no_authorize_upgrade():
    # Use the min_contract fixture which has no _authorizeUpgrade
    ast = build_ast(Path(__file__).parent / "fixtures" / "min_contract" / "MinV1.sol")
    assert detect_missing_upgrade_authorization(ast, source_file="MinV1.sol") == []

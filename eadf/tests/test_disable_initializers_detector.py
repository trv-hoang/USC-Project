from pathlib import Path
from eadf.module2_ast_diff.slither_ast import build_ast
from eadf.module3_vuln_detector.disable_initializers_detector import (
    detect_missing_disable_initializers,
)

ROOT = Path(__file__).parent / "fixtures" / "disable_init"


def test_flags_vulnerable():
    ast = build_ast(ROOT / "Vulnerable.sol")
    findings = detect_missing_disable_initializers(ast, source_file="Vulnerable.sol")
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_id == "missing-disable-initializers"
    assert f.severity == "High"


def test_no_finding_on_secure():
    ast = build_ast(ROOT / "Secure.sol")
    assert detect_missing_disable_initializers(ast, source_file="Secure.sol") == []


def test_no_finding_when_no_initializer_function():
    # MinV1.sol from earlier fixtures has no initializer-style function
    ast = build_ast(Path(__file__).parent / "fixtures" / "min_contract" / "MinV1.sol")
    assert detect_missing_disable_initializers(ast, source_file="MinV1.sol") == []

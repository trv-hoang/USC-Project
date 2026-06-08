# eadf/tests/test_slither_runner.py
import inspect
from pathlib import Path
from eadf.module3_vuln_detector.slither_runner import run_slither, _DETECTOR_CLASSES

REPO = Path(__file__).resolve().parents[2]


def test_detector_registry_contains_only_classes():
    # Guards against regressions of the inspect.isclass filter.
    assert _DETECTOR_CLASSES, "Detector registry must not be empty"
    for arg, cls in _DETECTOR_CLASSES.items():
        assert inspect.isclass(cls), f"{arg!r} maps to non-class {type(cls).__name__}"
        assert hasattr(cls, "ARGUMENT") and cls.ARGUMENT == arg


def test_detector_registry_includes_configured_detectors():
    from eadf.config import SLITHER_DETECTORS
    missing = [d for d in SLITHER_DETECTORS if d not in _DETECTOR_CLASSES]
    assert not missing, f"Configured detectors missing from Slither registry: {missing}"


def test_runs_and_returns_findings_list_for_vulnerable():
    v = REPO / "src" / "vulnerable" / "VulnerableLogicV1.sol"
    findings = run_slither(v)
    assert isinstance(findings, list)
    # We don't assert specific detector here — depends on slither version.
    # We do assert each finding has the canonical shape.
    for f in findings:
        assert f.id.startswith("v")
        assert f.detector_id
        assert f.severity in ("Critical", "High", "Medium", "Low", "Informational")

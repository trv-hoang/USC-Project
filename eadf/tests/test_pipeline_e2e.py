"""End-to-end success-criterion tests for the EADF MVP.

These three tests double as the MVP acceptance gate:
- Storage Collision detected with risk_level=Critical (Scenario 1)
- Uninitialized Implementation classified as Fix Vulnerability (Scenario 2)
- Unauthorized Upgrade detected via missing-upgrade-authorization (Scenario 3)
"""
import json
from pathlib import Path
from typer.testing import CliRunner
from eadf.cli import app

REPO = Path(__file__).resolve().parents[2]
runner = CliRunner()


def test_e2e_storage_collision(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    v1 = REPO / "src" / "vulnerable" / "VulnerableLogicV1.sol"
    v2 = REPO / "src" / "vulnerable" / "VulnerableLogicV2.sol"
    r = runner.invoke(app, ["run", "--local-v1", str(v1), "--local-v2", str(v2), "--run-id", "E2E_SC"])
    assert r.exit_code == 0, r.stdout

    report = json.loads((tmp_path / "work" / "E2E_SC" / "stage5_report.json").read_text())
    assert report["risk_level"] == "Critical"
    detector_ids = {f["detector_id"] for f in report["vulnerabilities"]["v2"]}
    assert "storage-collision-cross-version" in detector_ids
    high_conf_pairs = [p for p in report["matched_pairs"] if p["confidence"] > 0.6]
    assert any(p for p in high_conf_pairs)

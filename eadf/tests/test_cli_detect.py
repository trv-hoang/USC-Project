"""E2E test: eadf collect → diff → detect pipeline (Stage 1 → 2 → 3).

Uses the REAL upgrade pair (VulnerableLogicV1 → VulnerableLogicV2) as the
canonical Scenario 1 fixture. Verifies that:
- Stage 3 JSON is written at the expected path
- storage-collision-cross-version detector fires on V2
- upgrade_behavior is correctly classified
"""
import json
from pathlib import Path
from typer.testing import CliRunner
from eadf.cli import app

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]


def test_detect_pipeline(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    v1 = REPO / "src" / "vulnerable" / "VulnerableLogicV1.sol"
    v2 = REPO / "src" / "vulnerable" / "VulnerableLogicV2.sol"

    assert runner.invoke(app, ["collect", "--local-v1", str(v1), "--local-v2", str(v2), "--run-id", "D1"]).exit_code == 0
    assert runner.invoke(app, ["diff", "--run-id", "D1"]).exit_code == 0
    r = runner.invoke(app, ["detect", "--run-id", "D1"])
    assert r.exit_code == 0, r.stdout

    vuln_path = tmp_path / "work" / "D1" / "stage3_vulnerabilities.json"
    payload = json.loads(vuln_path.read_text())
    detector_ids = {f["detector_id"] for f in payload["v2"]}
    assert "storage-collision-cross-version" in detector_ids
    assert payload["upgrade_behavior"] in (
        "Introduce Vulnerability", "Invalid Upgrade",
    )

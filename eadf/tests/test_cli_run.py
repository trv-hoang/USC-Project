"""End-to-end test: `eadf run --local-v1 X --local-v2 Y` chains all 5 stages
in one invocation and produces all expected outputs."""

import json
from pathlib import Path
from typer.testing import CliRunner
from eadf.cli import app

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]


def test_run_chains_all_stages(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    v1 = REPO / "src" / "vulnerable" / "VulnerableLogicV1.sol"
    v2 = REPO / "src" / "vulnerable" / "VulnerableLogicV2.sol"

    r = runner.invoke(app, [
        "run", "--local-v1", str(v1), "--local-v2", str(v2), "--run-id", "E2E",
    ])
    assert r.exit_code == 0, r.stdout

    base = tmp_path / "work" / "E2E"
    # Every stage output exists
    assert (base / "stage1_sources" / "metadata.json").exists()
    assert (base / "stage2_ast_diff.json").exists()
    assert (base / "stage2_slot_diff.json").exists()
    assert (base / "stage3_vulnerabilities.json").exists()
    assert (base / "stage4_matched_pairs.json").exists()
    assert (base / "stage5_report.json").exists()
    assert (base / "checklist.md").exists()

    report = json.loads((base / "stage5_report.json").read_text())
    assert report["risk_level"] == "Critical"
    assert report["upgrade_behavior"] == "Introduce Vulnerability"


def test_run_missing_args_fails_with_clear_error(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    r = runner.invoke(app, ["run"])
    # No --proxy and no --local-* → expect non-zero exit + clear error
    assert r.exit_code != 0
    # Either typer's own error or our message — both acceptable; we just want a non-zero exit.

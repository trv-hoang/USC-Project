"""End-to-end test: chain collect -> diff -> detect -> match -> report on the
real Scenario 1 fixture pair. Verifies that Stage 5 produces both report.json
and checklist.md with the right top-level fields."""

import json
from pathlib import Path
from typer.testing import CliRunner
from eadf.cli import app

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]


def test_report_pipeline_storage_collision(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    v1 = REPO / "src" / "vulnerable" / "VulnerableLogicV1.sol"
    v2 = REPO / "src" / "vulnerable" / "VulnerableLogicV2.sol"

    for cmd in [
        ["collect", "--local-v1", str(v1), "--local-v2", str(v2), "--run-id", "R1"],
        ["diff", "--run-id", "R1"],
        ["detect", "--run-id", "R1"],
        ["match", "--run-id", "R1"],
        ["report", "--run-id", "R1"],
    ]:
        r = runner.invoke(app, cmd)
        assert r.exit_code == 0, f"{cmd[0]} failed: {r.stdout}"

    report_path = tmp_path / "work" / "R1" / "stage5_report.json"
    checklist_path = tmp_path / "work" / "R1" / "checklist.md"
    assert report_path.exists() and checklist_path.exists()

    report = json.loads(report_path.read_text())
    assert report["risk_level"] == "Critical"
    assert report["upgrade_behavior"] == "Introduce Vulnerability"
    assert report["storage_collision"]["detected"] is True
    assert report["storage_collision"]["severity"] == "Critical"

    md = checklist_path.read_text()
    assert "🔴 CRITICAL" in md
    assert "EADF Security Checklist — LOCAL_TEST" in md


def test_list_shows_run_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    (tmp_path / "work" / "alpha").mkdir(parents=True)
    (tmp_path / "work" / "beta").mkdir(parents=True)

    r = runner.invoke(app, ["list"])
    assert r.exit_code == 0
    assert "alpha" in r.stdout
    assert "beta" in r.stdout


def test_show_prints_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    run_dir = tmp_path / "work" / "demo"
    run_dir.mkdir(parents=True)
    (run_dir / "stage5_report.json").write_text(json.dumps({
        "proxy_address": "LOCAL_TEST",
        "upgrade_block": None,
        "impl_v1": "/x/V1.sol",
        "impl_v2": "/x/V2.sol",
        "upgrade_behavior": "Introduce Vulnerability",
        "storage_collision": {"detected": True, "severity": "Critical",
                              "affected_slots": [0], "details": "..."},
        "vulnerabilities": {"v1": [], "v2": [{"id": "v001"}], "introduced": [{"id": "v001"}], "fixed": []},
        "matched_pairs": [{"change_id": "c001", "vuln_id": "v001",
                           "scores": {}, "confidence": 0.8, "root_cause": "..."}],
        "risk_level": "Critical",
    }))

    r = runner.invoke(app, ["show", "demo"])
    assert r.exit_code == 0
    assert "Critical" in r.stdout
    assert "LOCAL_TEST" in r.stdout
    assert "Introduce Vulnerability" in r.stdout

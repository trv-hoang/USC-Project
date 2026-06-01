import json
from pathlib import Path
from typer.testing import CliRunner
from eadf.cli import app

runner = CliRunner()
MINI = Path(__file__).resolve().parent / "fixtures" / "eval_mini" / "manifest.toml"


def test_cli_evaluate_writes_outputs(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    out = tmp_path / "results"
    r = runner.invoke(app, [
        "evaluate", "--manifest", str(MINI), "--out", str(out),
    ])
    assert r.exit_code == 0, r.stdout
    metrics = json.loads((out / "metrics.json").read_text())
    assert "eadf" in metrics and "baseline" in metrics
    assert (out / "spec_tables.md").exists()
    # EADF should out-recall the baseline on this collision-containing mini set
    assert metrics["eadf"]["recall"] >= metrics["baseline"]["recall"]

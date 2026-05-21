import json
from pathlib import Path
from typer.testing import CliRunner
from eadf.cli import app

runner = CliRunner()

def test_collect_local(tmp_path, monkeypatch):
    v1 = tmp_path / "A.sol"; v1.write_text("contract A{}")
    v2 = tmp_path / "B.sol"; v2.write_text("contract B{}")
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))

    result = runner.invoke(app, [
        "collect", "--local-v1", str(v1), "--local-v2", str(v2), "--run-id", "T",
    ])
    assert result.exit_code == 0, result.stdout
    base = Path(tmp_path / "work" / "T" / "stage1_sources")
    assert (base / "v1" / "A.sol").exists()
    assert (base / "v2" / "B.sol").exists()
    assert json.loads((base / "metadata.json").read_text())["source_type"] == "local"

import json
from pathlib import Path
from typer.testing import CliRunner
from eadf.cli import app

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]

def test_diff_on_storage_collision_local(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    v1 = REPO / "src" / "secure" / "SecureLogicV1.sol"
    v2 = REPO / "src" / "vulnerable" / "VulnerableLogicV2.sol"

    r1 = runner.invoke(app, ["collect", "--local-v1", str(v1), "--local-v2", str(v2), "--run-id", "C1"])
    assert r1.exit_code == 0, r1.stdout
    r2 = runner.invoke(app, ["diff", "--run-id", "C1"])
    assert r2.exit_code == 0, r2.stdout

    slot_path = tmp_path / "work" / "C1" / "stage2_slot_diff.json"
    ast_path = tmp_path / "work" / "C1" / "stage2_ast_diff.json"
    assert slot_path.exists() and ast_path.exists()
    slot = json.loads(slot_path.read_text())
    assert slot["collisions"], "Expected at least one slot collision"

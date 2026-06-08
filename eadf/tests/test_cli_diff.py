"""End-to-end test for `eadf diff` on the real Scenario 1 upgrade pair.

Uses VulnerableLogicV1 → VulnerableLogicV2 (the actual upgrade pair from
test/1_StorageCollision.t.sol, both bare contracts with no OZ inheritance)
so the slot diff is clean and unambiguous.
"""
import json
from pathlib import Path
from typer.testing import CliRunner
from eadf.cli import app

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]


def test_diff_on_storage_collision_local(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    v1 = REPO / "src" / "vulnerable" / "VulnerableLogicV1.sol"
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

    # V1 layout: [value:uint256@0, owner:address@1]
    # V2 layout: [collisionVar:uint256@0, value:uint256@1, owner:address@2]
    # Expected collisions:
    #   slot 0: value (V1) → collisionVar (V2) — Critical (slot-0 + uint256 rule)
    #   slot 1: owner (V1) → value      (V2) — Critical (V1 name == "owner" rule)
    by_slot = {c["slot"]: c for c in slot["collisions"]}
    assert 0 in by_slot, "Expected slot-0 collision (value → collisionVar)"
    assert by_slot[0]["v1_var"] == "value"
    assert by_slot[0]["v2_var"] == "collisionVar"
    assert by_slot[0]["severity"] == "Critical"

    # The AST diff should record collisionVar as an INSERT at slot 0.
    ast = json.loads(ast_path.read_text())
    inserts = [c for c in ast["changes"] if c["op"] == "INSERT"]
    assert any(c["node_name"] == "collisionVar" and c["first_affected_slot"] == 0
               for c in inserts), "Expected INSERT for collisionVar at slot 0"

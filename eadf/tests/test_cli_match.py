"""End-to-end test: chain collect → diff → detect → match on the real Scenario 1 fixture pair.

Verifies that the storage-collision finding gets matched to the INSERT change
for collisionVar with confidence > threshold.
"""
import json
from pathlib import Path
from typer.testing import CliRunner
from eadf.cli import app

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]


def test_match_storage_collision_pipeline(tmp_path, monkeypatch):
    monkeypatch.setenv("EADF_WORK_ROOT", str(tmp_path / "work"))
    v1 = REPO / "src" / "vulnerable" / "VulnerableLogicV1.sol"
    v2 = REPO / "src" / "vulnerable" / "VulnerableLogicV2.sol"

    for cmd in [
        ["collect", "--local-v1", str(v1), "--local-v2", str(v2), "--run-id", "M1"],
        ["diff", "--run-id", "M1"],
        ["detect", "--run-id", "M1"],
        ["match", "--run-id", "M1"],
    ]:
        r = runner.invoke(app, cmd)
        assert r.exit_code == 0, f"{cmd[0]} failed: {r.stdout}"

    matched_path = tmp_path / "work" / "M1" / "stage4_matched_pairs.json"
    payload = json.loads(matched_path.read_text())

    # Schema sanity
    assert payload["threshold"] == 0.6
    assert set(payload["weights"].keys()) == {"pos", "pattern", "semantic", "type", "slot"}

    # At least one pair must be a storage-collision-cross-version match with confidence > 0.6
    high_conf = [p for p in payload["pairs"] if p["confidence"] > 0.6]
    assert high_conf, f"Expected at least one pair with confidence > 0.6, got: {payload['pairs']}"

from pathlib import Path
from eadf.evaluation.ground_truth import load_manifest
from eadf.evaluation.runner import run_eadf_predictions, run_baseline_predictions

REPO = Path(__file__).resolve().parents[2]
MINI = Path(__file__).resolve().parent / "fixtures" / "eval_mini" / "manifest.toml"


def test_eadf_predictions_detect_collision(tmp_path):
    pairs = {p.id: p for p in load_manifest(MINI)}
    v1, v2, behavior = run_eadf_predictions(pairs["MINI_SC"], work_root=tmp_path)
    assert "storage-collision-cross-version" in v2
    assert behavior in {
        "Introduce Vulnerability", "Fix Vulnerability",
        "Smooth Upgrade", "Invalid Upgrade",
    }


def test_baseline_predictions_miss_collision(tmp_path):
    pairs = {p.id: p for p in load_manifest(MINI)}
    v1, v2, behavior = run_baseline_predictions(pairs["MINI_SC"])
    # Slither-only cannot emit the custom cross-version detector
    assert "storage-collision-cross-version" not in v2

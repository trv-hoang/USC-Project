from pathlib import Path
from eadf.evaluation.ground_truth import load_manifest

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "eadf" / "benchmark" / "manifest.toml"


def test_manifest_loads_and_paths_exist():
    pairs = load_manifest(MANIFEST)
    assert len(pairs) >= 18
    for p in pairs:
        assert p.v1_path.exists(), p.v1_path
        assert p.v2_path.exists(), p.v2_path


def test_manifest_ids_unique():
    pairs = load_manifest(MANIFEST)
    ids = [p.id for p in pairs]
    assert len(ids) == len(set(ids))


def test_manifest_covers_all_behaviors():
    pairs = load_manifest(MANIFEST)
    behaviors = {p.behavior for p in pairs}
    assert behaviors == {
        "Introduce Vulnerability", "Fix Vulnerability",
        "Smooth Upgrade", "Invalid Upgrade",
    }

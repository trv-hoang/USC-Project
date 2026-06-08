from pathlib import Path
from eadf.evaluation.ground_truth import load_manifest, gt_vocabulary, BenchmarkPair

FIX = Path(__file__).resolve().parent / "fixtures" / "eval_mini" / "manifest.toml"


def test_load_manifest_parses_pairs():
    pairs = load_manifest(FIX)
    assert len(pairs) == 2
    p = {x.id: x for x in pairs}
    assert isinstance(p["MINI_SC"], BenchmarkPair)
    assert p["MINI_SC"].behavior == "Introduce Vulnerability"
    assert p["MINI_SC"].vulns_v2 == {"storage-collision-cross-version"}
    assert p["MINI_SC"].vulns_v1 == set()
    assert p["MINI_SC"].proxy_pattern == "UUPS"
    # paths are resolved relative to the manifest's directory
    assert p["MINI_SC"].v1_path.name == "v1.sol"
    assert p["MINI_SC"].v1_path.is_absolute()


def test_gt_vocabulary_is_union_of_all_vulns():
    pairs = load_manifest(FIX)
    assert gt_vocabulary(pairs) == {"storage-collision-cross-version"}


def test_load_manifest_rejects_bad_behavior(tmp_path):
    bad = tmp_path / "m.toml"
    bad.write_text(
        '[[pair]]\nid="X"\nname="x"\ncategory="c"\nv1="a.sol"\nv2="b.sol"\n'
        'behavior="Nonsense"\nvulns_v1=[]\nvulns_v2=[]\nproxy_pattern="UUPS"\n'
    )
    import pytest
    with pytest.raises(ValueError, match="behavior"):
        load_manifest(bad)

from eadf.models import Change, Finding, Location
from eadf.module4_matcher.semantic_scorer import calc_semantic_score


def test_insert_collision_high_score():
    change = Change(id="c1", op="INSERT", node_kind="StateVariable",
                    node_name="collisionVar", node_signature="",
                    v1_location=None, v2_location=Location("x.sol", 1),
                    first_affected_slot=0)
    vuln = Finding(id="v1", detector_id="storage-collision-cross-version",
                   severity="Critical", location=Location("x.sol", 1, function_name=None),
                   description="collisionVar overwrites value at slot 0",
                   extra={"v2_variable": "collisionVar"})
    assert calc_semantic_score(change, vuln) >= 0.6


def test_unrelated_pair_low_score():
    change = Change(id="c1", op="UPDATE", node_kind="Function", node_name="foo",
                    node_signature="", v1_location=None, v2_location=None,
                    first_affected_slot=None)
    vuln = Finding(id="v1", detector_id="storage-collision-cross-version",
                   severity="Critical", location=Location("x.sol", 1, function_name=None),
                   description="…", extra={})
    assert calc_semantic_score(change, vuln) <= 0.3

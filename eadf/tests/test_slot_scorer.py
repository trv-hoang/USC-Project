from eadf.models import Change, Location, SlotDiff, SlotCollision, SlotEntry, Finding
from eadf.module4_matcher.slot_scorer import calc_slot_score


def _vuln(detector_id="storage-collision-cross-version"):
    return Finding(id="v1", detector_id=detector_id, severity="Critical",
                   location=Location(file="x.sol", line=1), description="")


def _diff(collisions):
    return SlotDiff(v1_slots={}, v2_slots={}, collisions=collisions, packed_slots_present=False)


def test_returns_zero_for_unrelated_vuln():
    change = Change(id="c1", op="INSERT", node_kind="StateVariable", node_name="x",
                    node_signature="", v1_location=None, v2_location=None, first_affected_slot=0)
    assert calc_slot_score(change, _vuln("reentrancy-eth"), _diff([])) == 0.0


def test_insert_at_or_below_collision_scores_1():
    change = Change(id="c1", op="INSERT", node_kind="StateVariable", node_name="x",
                    node_signature="", v1_location=None, v2_location=None, first_affected_slot=0)
    diff = _diff([SlotCollision(slot=0, v1_var="a", v2_var="x", severity="Critical", reason="")])
    assert calc_slot_score(change, _vuln(), diff) == 1.0


def test_update_overlapping_collision_scores_1():
    change = Change(id="c1", op="UPDATE", node_kind="StateVariable", node_name="a",
                    node_signature="", v1_location=None, v2_location=None, first_affected_slot=2)
    diff = _diff([SlotCollision(slot=2, v1_var="a", v2_var="a", severity="Medium", reason="")])
    assert calc_slot_score(change, _vuln(), diff) == 1.0


def test_adjacent_slot_scores_half():
    change = Change(id="c1", op="UPDATE", node_kind="StateVariable", node_name="a",
                    node_signature="", v1_location=None, v2_location=None, first_affected_slot=1)
    diff = _diff([SlotCollision(slot=2, v1_var="x", v2_var="y", severity="Medium", reason="")])
    assert calc_slot_score(change, _vuln(), diff) == 0.5


def test_unrelated_change_scores_zero():
    change = Change(id="c1", op="UPDATE", node_kind="Function", node_name="f",
                    node_signature="", v1_location=None, v2_location=None, first_affected_slot=None)
    assert calc_slot_score(change, _vuln(), _diff([])) == 0.0

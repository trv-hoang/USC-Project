from eadf.models import Change, Finding, Location, SlotDiff, SlotCollision, SlotEntry, ASTDiffSet
from eadf.module4_matcher.confidence_scorer import match


def test_storage_collision_matched():
    change = Change(id="c1", op="INSERT", node_kind="StateVariable",
                    node_name="collisionVar", node_signature="",
                    v1_location=None, v2_location=Location("V.sol", 6),
                    first_affected_slot=0)
    ast_diff = ASTDiffSet(changes=[change], summary={"insert": 1, "delete": 0, "update": 0})
    vuln = Finding(id="v1", detector_id="storage-collision-cross-version",
                   severity="Critical", location=Location("V.sol", 6),
                   description="collisionVar overwrites slot 0",
                   extra={"v2_variable": "collisionVar"})
    slot_diff = SlotDiff(
        v1_slots={0: SlotEntry("value", "uint256", 32, 0)},
        v2_slots={0: SlotEntry("collisionVar", "uint256", 32, 0),
                  1: SlotEntry("value", "uint256", 32, 0)},
        collisions=[SlotCollision(slot=0, v1_var="value", v2_var="collisionVar",
                                  severity="Medium", reason="…")],
        packed_slots_present=False,
    )
    pairs = match(ast_diff, [vuln], slot_diff, v2_source_lines=["", "", "", "", "", "", "    uint256 public collisionVar;"])
    assert len(pairs) == 1
    assert pairs[0].confidence > 0.6
    assert pairs[0].change_id == "c1"

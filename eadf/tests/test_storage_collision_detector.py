from eadf.models import SlotDiff, SlotCollision, SlotEntry
from eadf.module3_vuln_detector.storage_collision_detector import detect_storage_collision


def test_emits_finding_per_collision():
    diff = SlotDiff(
        v1_slots={0: SlotEntry("value", "uint256", 32, 0)},
        v2_slots={0: SlotEntry("collisionVar", "uint256", 32, 0)},
        collisions=[SlotCollision(slot=0, v1_var="value", v2_var="collisionVar", severity="Medium", reason="…")],
        packed_slots_present=False,
    )
    findings = detect_storage_collision(diff, source_file="LogicV2.sol", v2_line_lookup={"collisionVar": 6})
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_id == "storage-collision-cross-version"
    assert f.severity == "Medium"
    assert f.location.file == "LogicV2.sol"
    assert f.location.line == 6
    assert f.extra["affected_slots"] == [0]
    assert f.extra["v1_variable"] == "value"
    assert f.extra["v2_variable"] == "collisionVar"


def test_no_finding_when_no_collisions():
    diff = SlotDiff(v1_slots={}, v2_slots={}, collisions=[], packed_slots_present=False)
    assert detect_storage_collision(diff, source_file="X.sol", v2_line_lookup={}) == []

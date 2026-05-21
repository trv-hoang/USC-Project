# eadf/tests/test_models.py
import json
from dataclasses import asdict
from eadf.models import (
    SourceMetadata, SourceBundle, StateVar, SlotEntry,
    Change, Location, Finding, SlotCollision, SlotDiff,
    ASTDiffSet, ConfidenceBreakdown, MatchedPair, Report,
    UpgradeBehavior, RiskLevel, StageResult,
)

def test_change_serialises_to_json():
    change = Change(
        id="c001", op="INSERT", node_kind="StateVariable",
        node_name="collisionVar", node_signature="uint256 collisionVar",
        v1_location=None,
        v2_location=Location(file="LogicV2.sol", line=6, col=5, function_name=None),
        first_affected_slot=0,
        extra={"type": "uint256", "visibility": "public"},
    )
    payload = json.dumps(asdict(change))
    parsed = json.loads(payload)
    assert parsed["id"] == "c001"
    assert parsed["first_affected_slot"] == 0

def test_upgrade_behavior_values():
    assert UpgradeBehavior.INTRODUCE.value == "Introduce Vulnerability"
    assert UpgradeBehavior.FIX.value == "Fix Vulnerability"
    assert UpgradeBehavior.SMOOTH.value == "Smooth Upgrade"
    assert UpgradeBehavior.INVALID.value == "Invalid Upgrade"

def test_risk_level_ordering():
    assert RiskLevel.CRITICAL.value == "Critical"
    assert RiskLevel.HIGH.value == "High"
    assert RiskLevel.MEDIUM.value == "Medium"
    assert RiskLevel.LOW.value == "Low"

"""Tests for checklist_generator — render Markdown per SPEC.md §5.6."""

from eadf.models import (
    Report, RiskLevel, UpgradeBehavior, MatchedPair, ConfidenceBreakdown,
)
from eadf.module5_reporter.checklist_generator import render_checklist


def _make_report(*, risk_level=RiskLevel.CRITICAL,
                 storage_collision=None, upgrade_behavior=UpgradeBehavior.INTRODUCE) -> Report:
    if storage_collision is None:
        storage_collision = {
            "detected": True, "severity": "Critical",
            "affected_slots": [0],
            "details": "Slot 0: value (V1) → collisionVar (V2)",
        }
    return Report(
        proxy_address="LOCAL_TEST",
        upgrade_block=None,
        impl_v1="/x/V1.sol",
        impl_v2="/x/V2.sol",
        upgrade_behavior=upgrade_behavior,
        storage_collision=storage_collision,
        vulnerabilities={"v1": [], "v2": [], "introduced": [], "fixed": []},
        matched_pairs=[],
        risk_level=risk_level,
    )


def test_critical_report_has_red_risk_banner():
    md = render_checklist(_make_report(risk_level=RiskLevel.CRITICAL))
    assert "🔴 CRITICAL" in md


def test_high_risk_uses_orange_banner():
    md = render_checklist(_make_report(risk_level=RiskLevel.HIGH))
    assert "🟠 HIGH" in md


def test_medium_risk_uses_yellow_banner():
    md = render_checklist(_make_report(risk_level=RiskLevel.MEDIUM))
    assert "🟡 MEDIUM" in md


def test_low_risk_uses_green_banner():
    md = render_checklist(_make_report(risk_level=RiskLevel.LOW))
    assert "🟢 LOW" in md


def test_contains_five_sections():
    md = render_checklist(_make_report())
    for section in [
        "### 1. Storage Layout Compatibility",
        "### 2. Initialization Security",
        "### 3. Access Control",
        "### 4. Post-Upgrade Logic",
        "### 5. Governance",
    ]:
        assert section in md, f"Missing section: {section}"


def test_includes_proxy_address_in_header():
    md = render_checklist(_make_report())
    assert "## EADF Security Checklist — LOCAL_TEST" in md


def test_storage_collision_warning_appears_when_detected():
    md = render_checklist(_make_report())
    assert "[!]" in md  # warning marker per §5.6
    assert "slot 0" in md.lower() or "Slot 0" in md


def test_no_storage_warning_when_no_collision():
    sc = {"detected": False, "severity": None, "affected_slots": [], "details": ""}
    md = render_checklist(_make_report(storage_collision=sc))
    assert "[!]" not in md
    # Section header still present
    assert "### 1. Storage Layout Compatibility" in md

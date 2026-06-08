"""Tests for the risk classifier 4-level rule."""
from eadf.module5_reporter.risk_classifier import classify_risk
from eadf.models import RiskLevel


def test_critical_when_storage_collision_critical():
    assert classify_risk(
        storage_collision_severity="Critical",
        introduced_vulns=[],
        upgrade_behavior="Smooth Upgrade"
    ) == RiskLevel.CRITICAL


def test_high_when_high_vuln_introduced():
    assert classify_risk(
        storage_collision_severity=None,
        introduced_vulns=[{"severity": "High"}],
        upgrade_behavior="Introduce Vulnerability"
    ) == RiskLevel.HIGH


def test_medium_when_introduce_only():
    assert classify_risk(
        storage_collision_severity=None,
        introduced_vulns=[{"severity": "Low"}],
        upgrade_behavior="Introduce Vulnerability"
    ) == RiskLevel.MEDIUM


def test_low_otherwise():
    assert classify_risk(
        storage_collision_severity=None,
        introduced_vulns=[],
        upgrade_behavior="Smooth Upgrade"
    ) == RiskLevel.LOW

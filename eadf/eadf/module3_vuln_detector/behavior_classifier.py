"""Classify upgrade behavior per SPEC.md §3.1."""
from ..models import UpgradeBehavior


def classify_behavior(v1_findings, v2_findings) -> UpgradeBehavior:
    if not v1_findings and v2_findings:
        return UpgradeBehavior.INTRODUCE
    if v1_findings and not v2_findings:
        return UpgradeBehavior.FIX
    if not v1_findings and not v2_findings:
        return UpgradeBehavior.SMOOTH
    return UpgradeBehavior.INVALID

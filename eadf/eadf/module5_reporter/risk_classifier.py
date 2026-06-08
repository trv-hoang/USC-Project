"""Risk classifier — 4-level rule from SPEC.md §5.6."""
from ..models import RiskLevel, UpgradeBehavior


def classify_risk(*, storage_collision_severity, introduced_vulns, upgrade_behavior) -> RiskLevel:
    """Classify upgrade risk according to the 4-level rule.

    Args:
        storage_collision_severity: Either "Critical" or None.
        introduced_vulns: List of vulnerability dicts with "severity" key.
        upgrade_behavior: String value of UpgradeBehavior enum.

    Returns:
        RiskLevel enum: CRITICAL, HIGH, MEDIUM, or LOW.
    """
    if storage_collision_severity == "Critical":
        return RiskLevel.CRITICAL
    if any(v["severity"] in ("High", "Critical") for v in introduced_vulns):
        return RiskLevel.HIGH
    if upgrade_behavior == UpgradeBehavior.INTRODUCE.value:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW

from eadf.module3_vuln_detector.behavior_classifier import classify_behavior
from eadf.models import UpgradeBehavior


def test_introduce():
    assert classify_behavior([], ["x"]) == UpgradeBehavior.INTRODUCE


def test_fix():
    assert classify_behavior(["x"], []) == UpgradeBehavior.FIX


def test_smooth():
    assert classify_behavior([], []) == UpgradeBehavior.SMOOTH


def test_invalid():
    assert classify_behavior(["x"], ["y"]) == UpgradeBehavior.INVALID

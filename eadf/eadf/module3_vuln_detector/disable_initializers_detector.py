"""Custom detector: contracts with initializer-style functions but no
_disableInitializers() call in their constructor.

Spec: design spec §8.3 (Custom cross-version detectors, third row). Closes
the gap for Scenario 2 (Uninitialized Implementation); Slither's stock
uninitialized-state detector looks for unwritten state vars, not for
missing _disableInitializers() in upgradeable-contract constructors.
"""
from __future__ import annotations
from ..models import Finding, Location


_INITIALIZER_MODIFIERS = {"initializer", "reinitializer"}


def detect_missing_disable_initializers(ast, source_file: str) -> list[Finding]:
    contract = ast._contract  # Slither Contract
    if not _has_initializer_function(contract):
        return []
    if _constructor_calls_disable_initializers(contract):
        return []
    sm = contract.source_mapping
    line = sm.lines[0] if sm and sm.lines else 0
    return [Finding(
        id="di001",
        detector_id="missing-disable-initializers",
        severity="High",
        location=Location(file=source_file, line=line, function_name=None),
        description=(
            "Contract defines an initializer-style function but its constructor "
            "does not call _disableInitializers(). Attackers can call initialize() "
            "directly on the implementation contract and take it over."
        ),
        extra={},
    )]


def _has_initializer_function(contract) -> bool:
    """Return True if the contract has a function that looks like an initializer.

    Two triggers (either is sufficient):
    1. Any function whose modifiers include 'initializer' or 'reinitializer'
       (handles OZ Initializable and self-contained fixture contracts).
    2. Any public/external function literally named 'initialize'
       (handles bare upgradeable contracts that don't use an explicit modifier,
       e.g. VulnerableLogicV1 which has no modifier on its initialize()).
    """
    for fn in contract.functions:
        # Trigger 1: modifier-based
        for m in fn.modifiers:
            if m.name in _INITIALIZER_MODIFIERS:
                return True
        # Trigger 2: function-name-based (public/external only to avoid
        # false-positives on internal helpers named _initialize*)
        if fn.name == "initialize" and fn.visibility in ("public", "external"):
            return True
    return False


def _constructor_calls_disable_initializers(contract) -> bool:
    for fn in contract.functions:
        if not fn.is_constructor:
            continue
        # Walk internal call edges; if any callee is named _disableInitializers, accept.
        for called in fn.internal_calls:
            # Slither's internal_calls returns Function/SolidityFunction objects.
            name = getattr(called, "name", None) or getattr(called, "full_name", None) or str(called)
            if "disableInitializers" in str(name):
                return True
        # Also walk modifiers calls (defensive)
        for m in fn.modifiers:
            if "disableInitializers" in (m.name or ""):
                return True
    return False

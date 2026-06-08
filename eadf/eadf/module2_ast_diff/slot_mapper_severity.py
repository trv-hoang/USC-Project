# eadf/eadf/module2_ast_diff/slot_mapper_severity.py
"""Severity heuristic for slot collisions. Design spec §9.2 (patched 2026-05-21).

Rule (in order — first match wins):
  Critical  if V1.name matches /owner|implementation|admin|proxy/i
            OR (slot == 0 AND V1.type ∈ privileged-shape set
                              {address, address payable, uint256, bytes32})
  High      if V1.type startswith "mapping("
            OR V1.name matches /balance|allow|allowance/i
            OR slot == 0   (any slot-0 collision not already Critical)
  Medium    otherwise

The slot-0 promotion exists because slot 0 is the first state slot, the most
likely write target in naive contracts (and the only slot writable via
BadProxy.upgradeTo). Promoting it satisfies the spec §15 success criterion
that the local Scenario 1 fixture (value:uint256 → collisionVar:uint256 at
slot 0) reaches risk_level=Critical end-to-end.
"""
import re

_CRITICAL_NAMES = re.compile(r"owner|implementation|admin|proxy", re.IGNORECASE)
_HIGH_NAMES = re.compile(r"balance|allow|allowance", re.IGNORECASE)
_PRIVILEGED_SHAPE_TYPES = frozenset({"address", "address payable", "uint256", "bytes32"})


def classify_severity(v1_entry, v2_entry, *, slot: int) -> tuple[str, str]:
    if _CRITICAL_NAMES.search(v1_entry.name):
        return ("Critical", f"V1 slot held a privileged variable '{v1_entry.name}'")
    if slot == 0 and v1_entry.type in _PRIVILEGED_SHAPE_TYPES:
        return (
            "Critical",
            f"Slot 0 holds a privileged-shaped value '{v1_entry.name}: {v1_entry.type}' (most exploitable target)",
        )
    if v1_entry.type.startswith("mapping(") or _HIGH_NAMES.search(v1_entry.name):
        return ("High", f"V1 slot held a financial/access mapping '{v1_entry.name}'")
    if slot == 0:
        return (
            "High",
            f"Slot 0 collision: '{v1_entry.name}: {v1_entry.type}' overwritten by '{v2_entry.name}: {v2_entry.type}'",
        )
    return ("Medium", f"V1 slot held '{v1_entry.name}', now '{v2_entry.name}'")

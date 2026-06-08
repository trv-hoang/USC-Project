"""Custom detector: _authorizeUpgrade(address) without an access-control modifier.

Spec: design spec §8.3 (Custom cross-version detectors). Closes the gap for
Scenario 3 — stock Slither detectors have no signal for this class.
"""
from __future__ import annotations
from ..models import Finding, Location

_ACL_MODIFIERS = {"onlyOwner", "onlyRole", "onlyAdmin", "onlyGovernor"}


def detect_missing_upgrade_authorization(ast, source_file: str) -> list[Finding]:
    contract = ast._contract  # Slither Contract
    findings: list[Finding] = []
    idx = 1
    for fn in contract.functions:
        if fn.name != "_authorizeUpgrade":
            continue
        # Only check the definition that belongs to this contract, not inherited
        # versions from parent contracts (e.g. UUPSUpgradeable's abstract stub).
        if fn.contract_declarer != contract:
            continue
        # Single-param (address newImplementation)
        if len(fn.parameters) != 1:
            continue
        modifier_names = {m.name for m in fn.modifiers}
        if modifier_names & _ACL_MODIFIERS:
            continue   # acceptably gated
        sm = fn.source_mapping
        line = sm.lines[0] if sm and sm.lines else 0
        findings.append(Finding(
            id=f"ua{idx:03d}",
            detector_id="missing-upgrade-authorization",
            severity="High",
            location=Location(file=source_file, line=line, function_name="_authorizeUpgrade"),
            description="_authorizeUpgrade(address) is missing an access-control modifier (e.g. onlyOwner). Anyone can authorise an upgrade.",
            extra={},
        ))
        idx += 1
    return findings

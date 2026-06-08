"""Custom cross-version storage collision detector — emits Slither-shaped Findings."""
from __future__ import annotations
from ..models import Finding, Location, SlotDiff


def detect_storage_collision(slot_diff: SlotDiff, source_file: str,
                             v2_line_lookup: dict[str, int]) -> list[Finding]:
    findings: list[Finding] = []
    for i, c in enumerate(slot_diff.collisions, start=1):
        line = v2_line_lookup.get(c.v2_var, 0)
        findings.append(Finding(
            id=f"sc{i:03d}",
            detector_id="storage-collision-cross-version",
            severity=c.severity,
            location=Location(file=source_file, line=line),
            description=c.reason,
            extra={
                "affected_slots": [c.slot],
                "v1_variable": c.v1_var,
                "v2_variable": c.v2_var,
            },
        ))
    return findings

"""Stage 5 — assemble the final EADF Report from Stages 1-4 JSON outputs.

Spec: design spec §8.5; thesis SPEC.md §5.6 (report schema).
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from ..models import (
    ConfidenceBreakdown, MatchedPair, Report, RiskLevel, UpgradeBehavior,
)
from ..workdir import WorkDir
from .risk_classifier import classify_risk


def build_report(workdir: Path) -> Report:
    """Read all four prior-stage JSON files in `workdir` and assemble a Report.

    Expected layout:
        workdir/
          stage1_sources/metadata.json
          stage2_slot_diff.json
          stage3_vulnerabilities.json
          stage4_matched_pairs.json
    """
    workdir = Path(workdir)
    metadata = _read_json(workdir / "stage1_sources" / "metadata.json")
    slot_diff = _read_json(workdir / "stage2_slot_diff.json")
    vulnerabilities = _read_json(workdir / "stage3_vulnerabilities.json")
    matched_raw = _read_json(workdir / "stage4_matched_pairs.json")

    upgrade_behavior = UpgradeBehavior(vulnerabilities.get("upgrade_behavior", "Smooth Upgrade"))

    storage_collision = _summarise_storage_collision(slot_diff)

    # Partition vulnerabilities into introduced / fixed
    v1_ids = {f["detector_id"] for f in vulnerabilities.get("v1", [])}
    v2_ids = {f["detector_id"] for f in vulnerabilities.get("v2", [])}
    introduced = [f for f in vulnerabilities.get("v2", []) if f["detector_id"] not in v1_ids]
    fixed = [f for f in vulnerabilities.get("v1", []) if f["detector_id"] not in v2_ids]

    matched_pairs = [_matched_pair_from_dict(p) for p in matched_raw.get("pairs", [])]

    risk_level = classify_risk(
        storage_collision_severity=storage_collision.get("severity"),
        introduced_vulns=introduced,
        upgrade_behavior=upgrade_behavior.value,
    )

    return Report(
        proxy_address=metadata.get("proxy_address", "UNKNOWN"),
        upgrade_block=metadata.get("upgrade_block"),
        impl_v1=metadata.get("v1", {}).get("path_or_address", ""),
        impl_v2=metadata.get("v2", {}).get("path_or_address", ""),
        upgrade_behavior=upgrade_behavior,
        storage_collision=storage_collision,
        vulnerabilities={
            "v1": vulnerabilities.get("v1", []),
            "v2": vulnerabilities.get("v2", []),
            "introduced": introduced,
            "fixed": fixed,
        },
        matched_pairs=matched_pairs,
        risk_level=risk_level,
    )


def dump_report(report: Report, path: Path) -> None:
    """Serialise a Report to JSON at the given path (atomic write via WorkDir helper)."""
    # Reuse WorkDir's atomic writer for consistency
    wd = WorkDir(root=path.parent.parent, run_id=path.parent.name)
    wd.write_json(path, report)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _summarise_storage_collision(slot_diff: dict) -> dict:
    collisions = slot_diff.get("collisions", [])
    if not collisions:
        return {
            "detected": False,
            "severity": None,
            "affected_slots": [],
            "details": "",
        }
    # Highest severity across all collisions (Critical > High > Medium)
    severity_rank = {"Critical": 3, "High": 2, "Medium": 1}
    worst = max(collisions, key=lambda c: severity_rank.get(c.get("severity", "Medium"), 0))
    return {
        "detected": True,
        "severity": worst["severity"],
        "affected_slots": sorted({c["slot"] for c in collisions}),
        "details": "; ".join(
            f"Slot {c['slot']}: {c['v1_var']} (V1) -> {c['v2_var']} (V2)"
            for c in collisions
        ),
    }


def _matched_pair_from_dict(d: dict) -> MatchedPair:
    return MatchedPair(
        change_id=d["change_id"],
        vuln_id=d["vuln_id"],
        scores=ConfidenceBreakdown(**d["scores"]),
        confidence=d["confidence"],
        root_cause=d.get("root_cause", ""),
    )

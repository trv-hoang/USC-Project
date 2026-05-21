"""Tests for json_reporter.build_report — assembles final Stage 5 Report from
the JSON outputs of Stages 1-4. Uses fixture files to avoid the cost of
running the upstream pipeline."""

import json
import shutil
from pathlib import Path

from eadf.module5_reporter.json_reporter import build_report, dump_report
from eadf.models import RiskLevel, UpgradeBehavior

FIXTURES = Path(__file__).parent / "fixtures" / "stage_chain"


def _set_up_workdir(tmp_path: Path) -> Path:
    """Copy fixture stage files into a temp workdir mimicking a real run layout."""
    work = tmp_path / "run_test"
    work.mkdir()
    (work / "stage1_sources").mkdir()
    shutil.copy(FIXTURES / "metadata.json", work / "stage1_sources" / "metadata.json")
    shutil.copy(FIXTURES / "stage2_slot_diff.json", work / "stage2_slot_diff.json")
    shutil.copy(FIXTURES / "stage3_vulnerabilities.json", work / "stage3_vulnerabilities.json")
    shutil.copy(FIXTURES / "stage4_matched_pairs.json", work / "stage4_matched_pairs.json")
    return work


def test_build_report_assembles_all_stages(tmp_path):
    work = _set_up_workdir(tmp_path)
    report = build_report(work)
    assert report.proxy_address == "LOCAL_TEST"
    assert report.upgrade_behavior == UpgradeBehavior.INTRODUCE
    assert report.risk_level == RiskLevel.CRITICAL
    assert report.storage_collision["detected"] is True
    assert report.storage_collision["severity"] == "Critical"
    assert report.storage_collision["affected_slots"] == [0]
    assert len(report.matched_pairs) == 1
    assert report.matched_pairs[0].confidence == 0.8025
    # Vulnerabilities partition: introduced = v2-only, fixed = v1-only
    assert report.vulnerabilities["v1"] == []
    assert len(report.vulnerabilities["v2"]) == 1
    assert len(report.vulnerabilities["introduced"]) == 1
    assert report.vulnerabilities["fixed"] == []


def test_dump_report_writes_json(tmp_path):
    work = _set_up_workdir(tmp_path)
    report = build_report(work)
    out_path = work / "stage5_report.json"
    dump_report(report, out_path)
    payload = json.loads(out_path.read_text())
    assert payload["risk_level"] == "Critical"
    assert payload["upgrade_behavior"] == "Introduce Vulnerability"
    assert payload["matched_pairs"][0]["change_id"] == "c001"


def test_build_report_no_collision_smooth_upgrade(tmp_path):
    """When there are no collisions, no v2 findings, and SMOOTH behavior ->
    risk_level should be Low and storage_collision.detected should be False."""
    work = tmp_path / "r2"
    work.mkdir()
    (work / "stage1_sources").mkdir()
    (work / "stage1_sources" / "metadata.json").write_text(json.dumps({
        "source_type": "local",
        "v1": {"path_or_address": "/x.sol", "label": "X", "compiler": "0.8.24"},
        "v2": {"path_or_address": "/x.sol", "label": "X", "compiler": "0.8.24"},
        "fetched_at": "2026-05-21T18:00:00+00:00",
        "proxy_address": "LOCAL_TEST",
        "upgrade_block": None,
    }))
    (work / "stage2_slot_diff.json").write_text(json.dumps({
        "v1_slots": {}, "v2_slots": {}, "collisions": [], "packed_slots_present": False
    }))
    (work / "stage3_vulnerabilities.json").write_text(json.dumps({
        "v1": [], "v2": [], "upgrade_behavior": "Smooth Upgrade"
    }))
    (work / "stage4_matched_pairs.json").write_text(json.dumps({
        "threshold": 0.6, "weights": {}, "pairs": [],
        "unmatched_changes": [], "unmatched_vulns": []
    }))

    report = build_report(work)
    assert report.risk_level == RiskLevel.LOW
    assert report.storage_collision["detected"] is False
    assert report.upgrade_behavior == UpgradeBehavior.SMOOTH

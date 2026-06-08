"""Benchmark runner: drive full EADF and a Slither-only baseline over every
pair, then compute metrics + EDA and render the SPEC tables.

Run from the repo root so Slither resolves @openzeppelin remappings.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path

from .ground_truth import BenchmarkPair, load_manifest, gt_vocabulary
from .metrics import (
    Sample, compute_detection_metrics, compute_behavior_accuracy, render_baseline_table,
)
from .eda import compute_eda
from .contract_stats import analyze_contract


def run_eadf_predictions(pair: BenchmarkPair, work_root: Path) -> tuple[set[str], set[str], str]:
    """Run the full 5-stage pipeline; return (v1 detectors, v2 detectors, behavior)."""
    from ..cli import run as cli_run
    os.environ["EADF_WORK_ROOT"] = str(work_root)
    run_id = f"BENCH_{pair.id}"
    cli_run(proxy=None, local_v1=pair.v1_path, local_v2=pair.v2_path,
            run_id=run_id, from_stage=1)
    vuln = json.loads((Path(work_root) / run_id / "stage3_vulnerabilities.json").read_text())
    v1 = {f["detector_id"] for f in vuln.get("v1", [])}
    v2 = {f["detector_id"] for f in vuln.get("v2", [])}
    # Fail loud if the pipeline didn't record a behavior — an evaluation harness
    # must not silently score a pair as "Smooth Upgrade" on a missing key.
    return v1, v2, vuln["upgrade_behavior"]


def run_baseline_predictions(pair: BenchmarkPair) -> tuple[set[str], set[str], str]:
    """Slither-only baseline: stock detectors, no custom detectors, no slot diff."""
    from ..module3_vuln_detector.slither_runner import run_slither
    from ..module3_vuln_detector.behavior_classifier import classify_behavior
    f1 = run_slither(pair.v1_path)
    f2 = run_slither(pair.v2_path)
    v1 = {f.detector_id for f in f1}
    v2 = {f.detector_id for f in f2}
    behavior = classify_behavior(f1, f2).value
    return v1, v2, behavior


@dataclass
class EvaluationResult:
    n_pairs: int
    in_scope: list[str]
    eadf: dict
    baseline: dict
    eadf_behavior: dict
    baseline_behavior: dict


def evaluate(manifest_path: Path, work_root: Path, out_dir: Path) -> EvaluationResult:
    pairs = load_manifest(manifest_path)
    in_scope = gt_vocabulary(pairs)

    eadf_samples: list[Sample] = []
    base_samples: list[Sample] = []
    eadf_beh: list[tuple[str, str]] = []
    base_beh: list[tuple[str, str]] = []

    for p in pairs:
        e_v1, e_v2, e_behavior = run_eadf_predictions(p, work_root)
        b_v1, b_v2, b_behavior = run_baseline_predictions(p)
        eadf_samples.append(Sample(p.id, "v1", e_v1, p.vulns_v1))
        eadf_samples.append(Sample(p.id, "v2", e_v2, p.vulns_v2))
        base_samples.append(Sample(p.id, "v1", b_v1, p.vulns_v1))
        base_samples.append(Sample(p.id, "v2", b_v2, p.vulns_v2))
        eadf_beh.append((p.behavior, e_behavior))
        base_beh.append((p.behavior, b_behavior))

    eadf_m = compute_detection_metrics(eadf_samples, in_scope)
    base_m = compute_detection_metrics(base_samples, in_scope)
    eadf_bm = compute_behavior_accuracy(eadf_beh)
    base_bm = compute_behavior_accuracy(base_beh)
    eda = compute_eda(pairs, analyze_contract)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.json").write_text(json.dumps({
        "in_scope": sorted(in_scope),
        "eadf": asdict(eadf_m),
        "baseline": asdict(base_m),
        "eadf_behavior": asdict(eadf_bm),
        "baseline_behavior": asdict(base_bm),
    }, indent=2, default=str))

    spec_md = "\n\n".join([
        "<!-- ===== SPEC §7.2 baseline table ===== -->",
        render_baseline_table(eadf_m, base_m),
        f"\nEADF behavior accuracy: {eadf_bm.accuracy*100:.1f}% "
        f"({eadf_bm.correct}/{eadf_bm.total}); "
        f"baseline: {base_bm.accuracy*100:.1f}% ({base_bm.correct}/{base_bm.total})",
        "<!-- ===== SPEC §6.5.2 EDA tables ===== -->",
        eda.render_all(),
    ])
    (out_dir / "spec_tables.md").write_text(spec_md)

    return EvaluationResult(
        n_pairs=len(pairs), in_scope=sorted(in_scope),
        eadf=asdict(eadf_m), baseline=asdict(base_m),
        eadf_behavior=asdict(eadf_bm), baseline_behavior=asdict(base_bm),
    )

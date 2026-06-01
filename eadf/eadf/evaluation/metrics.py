"""Detection (P/R/F1) and behavior-accuracy metrics for the EADF benchmark.

Scoring is restricted to an in-scope detector vocabulary (the manifest's
ground-truth detector_ids). Predicted detectors outside that set are ignored,
so tools are not penalized for emitting informational/style checks we never
labeled. See plan Design Decision #2.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Sample:
    pair_id: str
    version: str          # "v1" | "v2"
    predicted: set[str]
    expected: set[str]


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


@dataclass
class DetectionMetrics:
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    per_detector: dict[str, dict] = field(default_factory=dict)


def compute_detection_metrics(samples: list[Sample], in_scope: set[str]) -> DetectionMetrics:
    tp = fp = fn = 0
    per: dict[str, dict[str, int]] = {d: {"tp": 0, "fp": 0, "fn": 0} for d in in_scope}
    for s in samples:
        pred = s.predicted & in_scope
        exp = s.expected & in_scope
        for d in pred & exp:
            tp += 1; per[d]["tp"] += 1
        for d in pred - exp:
            fp += 1; per[d]["fp"] += 1
        for d in exp - pred:
            fn += 1; per[d]["fn"] += 1
    precision, recall, f1 = _prf(tp, fp, fn)
    per_detector = {}
    for d, c in per.items():
        p, r, f = _prf(c["tp"], c["fp"], c["fn"])
        per_detector[d] = {**c, "precision": p, "recall": r, "f1": f}
    return DetectionMetrics(tp, fp, fn, precision, recall, f1, per_detector)


@dataclass
class BehaviorMetrics:
    total: int
    correct: int
    accuracy: float
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)


def compute_behavior_accuracy(samples: list[tuple[str, str]]) -> BehaviorMetrics:
    """samples: list of (expected_behavior, predicted_behavior)."""
    total = len(samples)
    correct = sum(1 for e, p in samples if e == p)
    confusion: dict[str, dict[str, int]] = {}
    for e, p in samples:
        confusion.setdefault(e, {}).setdefault(p, 0)
        confusion[e][p] += 1
    accuracy = correct / total if total else 0.0
    return BehaviorMetrics(total, correct, accuracy, confusion)


def _pct(x: float) -> str:
    return f"{x * 100:.2f}%"


def render_baseline_table(eadf: DetectionMetrics, baseline: DetectionMetrics) -> str:
    """Render the SPEC §7.2 comparison table (Markdown)."""
    rows = [
        "| Phương pháp | Precision | Recall | F1-score |",
        "|---|---|---|---|",
        f"| Slither đơn thuần | {_pct(baseline.precision)} | {_pct(baseline.recall)} | {_pct(baseline.f1)} |",
        "| USCSA (Li et al., 2026) | 92.26% | 89.67% | 90.95% |",
        f"| **EADF (đề tài)** | {_pct(eadf.precision)} | {_pct(eadf.recall)} | {_pct(eadf.f1)} |",
    ]
    return "\n".join(rows)

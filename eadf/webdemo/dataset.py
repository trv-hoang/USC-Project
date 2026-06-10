"""Read the offline benchmark (Dataset B) + evaluation results for the demo's
Dataset & Evaluation view. Pure reads of manifest.toml and results/metrics.json —
no pipeline run.
"""
from __future__ import annotations

import json
import tomllib
from collections import Counter
from pathlib import Path

# webdemo/ -> parents[1] == repo/eadf ; benchmark lives in repo/eadf/benchmark
BENCH = Path(__file__).resolve().parents[1] / "benchmark"


def _pairs() -> list[dict]:
    data = tomllib.loads((BENCH / "manifest.toml").read_text())
    return data["pair"]


def _counter_list(counter: Counter) -> list[dict]:
    """Sorted (desc) list of {label, count} for stable rendering."""
    return [
        {"label": label, "count": count}
        for label, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def dataset() -> dict:
    pairs = _pairs()
    metrics = json.loads((BENCH / "results" / "metrics.json").read_text())

    behavior = Counter(p["behavior"] for p in pairs)
    proxy = Counter(p["proxy_pattern"] for p in pairs)
    # vuln-type distribution over ground truth, counting each detector once per pair
    # (set union of v1/v2) to match eda.py / SPEC §6.5.2 B.4 exactly.
    vulns = Counter(
        v for p in pairs
        for v in (set(p.get("vulns_v1", [])) | set(p.get("vulns_v2", [])))
    )

    return {
        "total": len(pairs),
        "behavior": _counter_list(behavior),
        "proxy": _counter_list(proxy),
        "vulns": _counter_list(vulns),
        "metrics": {
            "eadf": {k: metrics["eadf"][k] for k in ("precision", "recall", "f1")},
            "baseline": {k: metrics["baseline"][k] for k in ("precision", "recall", "f1")},
            "eadf_behavior_acc": metrics["eadf_behavior"]["accuracy"],
            "baseline_behavior_acc": metrics["baseline_behavior"]["accuracy"],
        },
    }

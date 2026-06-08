"""Semantic score with 6 features per SPEC.md §5.5.

MVP uses rapidfuzz for F1 and a TOML lookup for F2/F4/F5/F6. The lookup table
ships inside the package (eadf/data/semantic_tables.toml) so it works after
`pip install` as well as in editable installs.
"""
from __future__ import annotations

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]

from importlib.resources import files

from rapidfuzz import fuzz

from ..models import Change, Finding

# Load tables once at import time from package data
_T = tomllib.loads((files("eadf") / "data" / "semantic_tables.toml").read_text())


def _lookup(section: str, key: str) -> float:
    return float(_T.get(section, {}).get(key, 0.0))


def calc_semantic_score(change: Change, vuln: Finding) -> float:
    # F1 — name fuzzy similarity (0..1)
    target = vuln.location.function_name or vuln.extra.get("v2_variable", "")
    f1 = fuzz.ratio(change.node_name or "", target or "") / 100.0
    # F2
    f2 = _lookup("ast_node_relevance", f"{change.op}.{change.node_kind}.{vuln.detector_id}")
    # F3 — keyword overlap with description (cheap)
    desc = (vuln.description or "").lower()
    f3 = 1.0 if change.node_name and change.node_name.lower() in desc else 0.0
    # F4
    f4 = _lookup("op_detector", f"{change.op}.{vuln.detector_id}")
    # F5
    f5 = _lookup("trait", f"{change.node_kind}.{vuln.detector_id}")
    # F6
    f6 = _lookup("impact", f"{change.node_kind}.{vuln.detector_id}")

    score = (0.30 * f1 + 0.20 * f2 + 0.15 * f3 + 0.15 * f4 + 0.10 * f5 + 0.10 * f6)
    return min(1.0, score)

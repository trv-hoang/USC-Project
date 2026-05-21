"""Pattern score — keyword overlap in ±5 lines of context."""
from __future__ import annotations

VULN_KEYWORDS = {
    "uninitialized-state": {"initialize", "constructor", "_disableInitializers"},
    "storage-collision-cross-version": {"slot", "storage", "layout"},
    "controlled-delegatecall": {"delegatecall"},
    "suicidal": {"selfdestruct"},
    "reentrancy-eth": {"call", "transfer", "send"},
    "reentrancy-no-eth": {"call"},
    "missing-zero-check": {"address(0)"},
    "uninitialized-local": {"uninitialized"},
}


def calc_pattern_score(context_lines: list[str], detector_id: str) -> float:
    kws = VULN_KEYWORDS.get(detector_id, set())
    if not kws:
        return 0.0
    text = "\n".join(context_lines).lower()
    hits = sum(1 for kw in kws if kw.lower() in text)
    return min(1.0, hits * 0.1)

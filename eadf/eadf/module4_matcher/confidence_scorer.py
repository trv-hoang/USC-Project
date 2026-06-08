"""Combine 5 sub-scores into a single confidence and produce matched pairs."""
from __future__ import annotations
from ..config import WEIGHTS, CONFIDENCE_THRESHOLD
from ..models import ASTDiffSet, ConfidenceBreakdown, Finding, MatchedPair, SlotDiff
from .pos_scorer import calc_pos_score
from .pattern_scorer import calc_pattern_score
from .semantic_scorer import calc_semantic_score
from .type_scorer import calc_type_score
from .slot_scorer import calc_slot_score


def compute_confidence(change, vuln: Finding, slot_diff: SlotDiff,
                       v2_source_lines: list[str]) -> ConfidenceBreakdown:
    change_line = (change.v2_location or change.v1_location).line if (change.v2_location or change.v1_location) else 0
    vuln_line = vuln.location.line
    context = _context(v2_source_lines, change_line, window=5)

    return ConfidenceBreakdown(
        pos=calc_pos_score(change_line, vuln_line),
        pattern=calc_pattern_score(context, vuln.detector_id),
        semantic=calc_semantic_score(change, vuln),
        type=calc_type_score(change.op, change.node_kind, vuln.detector_id),
        slot=calc_slot_score(change, vuln, slot_diff),
    )


def _context(lines: list[str], target_line: int, window: int) -> list[str]:
    if not lines or target_line <= 0:
        return []
    lo = max(0, target_line - 1 - window)
    hi = min(len(lines), target_line + window)
    return lines[lo:hi]


def match(ast_diff: ASTDiffSet, v2_findings: list[Finding], slot_diff: SlotDiff,
          v2_source_lines: list[str], threshold: float = CONFIDENCE_THRESHOLD) -> list[MatchedPair]:
    pairs: list[MatchedPair] = []
    matched_changes: set[str] = set()
    matched_vulns: set[str] = set()

    candidates = []
    for change in ast_diff.changes:
        for vuln in v2_findings:
            br = compute_confidence(change, vuln, slot_diff, v2_source_lines)
            conf = br.total
            if conf > threshold:
                candidates.append((conf, change, vuln, br))

    # Greedy: highest confidence first
    candidates.sort(key=lambda x: -x[0])
    for conf, change, vuln, br in candidates:
        if change.id in matched_changes or vuln.id in matched_vulns:
            continue
        root = _root_cause(change, vuln)
        pairs.append(MatchedPair(
            change_id=change.id, vuln_id=vuln.id,
            scores=br, confidence=round(conf, 4), root_cause=root,
        ))
        matched_changes.add(change.id)
        matched_vulns.add(vuln.id)
    return pairs


def _root_cause(change, vuln) -> str:
    if vuln.detector_id == "storage-collision-cross-version" and change.op == "INSERT":
        return f"INSERT VarDecl {change.node_name} shifts subsequent slot layout"
    return f"{change.op} {change.node_kind} {change.node_name} ↔ {vuln.detector_id}"

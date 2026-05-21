"""S_slot — the novel storage-collision-aware dimension of the confidence formula.

Spec: design spec §9.4. Asymmetric INSERT branch is intentional — do NOT
normalise to overlaps_collision; that would silently change semantics.
"""
from __future__ import annotations
from ..models import Change, Finding, SlotDiff


def overlaps_collision(change: Change, slot_diff: SlotDiff) -> bool:
    s = change.first_affected_slot
    return s is not None and any(c.slot == s for c in slot_diff.collisions)


def affects_adjacent_slot(change: Change, slot_diff: SlotDiff) -> bool:
    s = change.first_affected_slot
    return s is not None and any(abs(c.slot - s) == 1 for c in slot_diff.collisions)


def calc_slot_score(change: Change, vuln: Finding, slot_diff: SlotDiff) -> float:
    if vuln.detector_id != "storage-collision-cross-version":
        return 0.0
    if change.first_affected_slot is None:
        return 0.0
    # INSERT at slot N shifts V1 variables originally at slots >= N up by one,
    # producing collisions at slots N, N+1, ... in V2. So a collision at any
    # slot >= N is attributable to this INSERT. Asymmetric with UPDATE/MOVE
    # below (which uses exact-overlap) — do not normalise to overlaps_collision
    # or the semantics change silently.
    if change.op == "INSERT" and any(
        c.slot >= change.first_affected_slot for c in slot_diff.collisions
    ):
        return 1.0
    if change.op in {"UPDATE", "MOVE"} and overlaps_collision(change, slot_diff):
        return 1.0
    if affects_adjacent_slot(change, slot_diff):
        return 0.5
    return 0.0

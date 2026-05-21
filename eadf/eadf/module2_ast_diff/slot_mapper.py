"""Compute Solidity storage slot mapping per packing rules.

Spec: SPEC.md §5.3 + design spec §9.1. MVP limitation: only the first variable
per packed slot is recorded; packed_slots_present in stage2_slot_diff.json
signals when this matters.
"""
from __future__ import annotations
import re

from ..models import SlotEntry, StateVar

_INT_RE = re.compile(r"^(u?int)(\d+)$")
_FIXED_ARRAY_RE = re.compile(r"^(.+)\[(\d+)\]$")


def size_of(type_str: str) -> int:
    """Return byte size of a state variable type within a single storage slot.

    Dynamic types (mapping/dynamic array) return 32 (their slot is the keccak base).
    Fixed-size arrays return total bytes across all slots (size * 32 in MVP for
    full-slot element types, or element_size * count for sub-slot element types).
    """
    if type_str.startswith("mapping("):
        return 32
    if type_str.endswith("[]"):
        return 32
    fixed = _FIXED_ARRAY_RE.match(type_str)
    if fixed:
        inner, n = fixed.group(1), int(fixed.group(2))
        return size_of(inner) * n
    if type_str in ("address", "address payable"):
        return 20
    if type_str == "bool":
        return 1
    if type_str.startswith("bytes") and type_str != "bytes":
        # bytes1..bytes32
        try:
            return int(type_str[5:])
        except ValueError:
            return 32
    m = _INT_RE.match(type_str)
    if m:
        return int(m.group(2)) // 8
    # Default: assume struct/string/bytes/contract reference fits in one slot ref
    return 32


def _is_dynamic(type_str: str) -> bool:
    return type_str.startswith("mapping(") or type_str.endswith("[]") or type_str in {"string", "bytes"}


def compute_slot_mapping(state_vars: list[StateVar]) -> dict[int, SlotEntry]:
    """Return a mapping from storage slot index to the first StateVar placed there.

    Follows Solidity's storage packing rules:
    - Variables smaller than 32 bytes are packed together if they fit.
    - When a new variable does not fit in the current slot, a new slot is started.
    - Dynamic types (mappings, dynamic arrays) always occupy their own full slot.
    - Fixed arrays spanning multiple slots advance the slot pointer accordingly.

    MVP limitation: only the *first* variable assigned to each slot is recorded.
    Use packed_slots_present() to detect when this matters.
    """
    slot: int = 0
    offset: int = 0
    mapping: dict[int, SlotEntry] = {}

    for v in state_vars:
        size = size_of(v.type)

        if _is_dynamic(v.type):
            # Dynamic types always start on a fresh slot
            if offset > 0:
                slot += 1
                offset = 0
            mapping[slot] = SlotEntry(name=v.name, type=v.type, size=32, offset=0)
            slot += 1

        elif size > 32:
            # Fixed array spanning multiple slots: must start at a fresh slot
            if offset > 0:
                slot += 1
                offset = 0
            mapping[slot] = SlotEntry(name=v.name, type=v.type, size=size, offset=0)
            slot += size // 32
            offset = 0

        elif size == 32:
            # Full-slot variable: must start at a fresh slot
            if offset > 0:
                slot += 1
                offset = 0
            mapping[slot] = SlotEntry(name=v.name, type=v.type, size=size, offset=0)
            slot += 1
            offset = 0

        elif offset + size > 32:
            # Doesn't fit in current slot — start a new one
            slot += 1
            offset = 0
            mapping[slot] = SlotEntry(name=v.name, type=v.type, size=size, offset=0)
            offset = size

        else:
            # Packing: fits in current slot alongside existing variable(s)
            # Only record the first variable placed in this slot (MVP limitation)
            if slot not in mapping:
                mapping[slot] = SlotEntry(name=v.name, type=v.type, size=size, offset=offset)
            offset += size

    return mapping


def diff_slot_maps(v1: dict[int, "SlotEntry"], v2: dict[int, "SlotEntry"]) -> "SlotDiff":
    """Compare two slot mappings and return a SlotDiff with per-slot collisions.

    A collision is recorded whenever the same slot index holds variables with
    different (name, type) pairs across v1 and v2.  Severity is assigned by
    classify_severity (design spec §9.2, patched 2026-05-21).
    """
    from .slot_mapper_severity import classify_severity
    from ..models import SlotDiff, SlotCollision

    collisions: list[SlotCollision] = []
    all_slots = sorted(set(v1.keys()) | set(v2.keys()))
    for s in all_slots:
        a, b = v1.get(s), v2.get(s)
        if a is None or b is None:
            continue
        if (a.name, a.type) != (b.name, b.type):
            sev, reason = classify_severity(a, b, slot=s)
            collisions.append(SlotCollision(
                slot=s, v1_var=a.name, v2_var=b.name, severity=sev, reason=reason,
            ))
    return SlotDiff(v1_slots=v1, v2_slots=v2, collisions=collisions, packed_slots_present=False)


def packed_slots_present(state_vars: list[StateVar]) -> bool:
    """Return True if any storage slot contains more than one variable."""
    slot: int = 0
    offset: int = 0
    per_slot: dict[int, int] = {}

    for v in state_vars:
        size = size_of(v.type)

        if _is_dynamic(v.type):
            if offset > 0:
                slot += 1
                offset = 0
            per_slot[slot] = per_slot.get(slot, 0) + 1
            slot += 1
            offset = 0

        elif size > 32:
            if offset > 0:
                slot += 1
                offset = 0
            per_slot[slot] = per_slot.get(slot, 0) + 1
            slot += size // 32
            offset = 0

        elif size == 32:
            if offset > 0:
                slot += 1
                offset = 0
            per_slot[slot] = per_slot.get(slot, 0) + 1
            slot += 1
            offset = 0

        elif offset + size > 32:
            slot += 1
            offset = 0
            per_slot[slot] = per_slot.get(slot, 0) + 1
            offset = size

        else:
            per_slot[slot] = per_slot.get(slot, 0) + 1
            offset += size

    return any(count > 1 for count in per_slot.values())

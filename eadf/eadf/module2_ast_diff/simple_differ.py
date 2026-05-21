"""Simple AST diff — compares state variables, functions, and modifiers by name.

For MVP this is sufficient; GumTreeDiffer would replace this for finer-grained
node-level edits (tracked as future work).
"""
from __future__ import annotations

from ..models import ASTDiffSet, Change, Location, StateVar
from .slot_mapper import compute_slot_mapping


class SimpleASTDiffer:
    def diff(
        self,
        v1_ast,
        v2_ast,
        v1_state_vars: list[StateVar],
        v2_state_vars: list[StateVar],
    ) -> ASTDiffSet:
        changes: list[Change] = []
        idx = 1

        # Index by name
        v1_by_name = {v.name: v for v in v1_state_vars}
        v2_by_name = {v.name: v for v in v2_state_vars}
        v1_slots_by_name = _slots_by_name(v1_state_vars)
        v2_slots_by_name = _slots_by_name(v2_state_vars)

        # INSERTs (in v2 not v1)
        for v in v2_state_vars:
            if v.name not in v1_by_name:
                changes.append(Change(
                    id=f"c{idx:03d}",
                    op="INSERT",
                    node_kind="StateVariable",
                    node_name=v.name,
                    node_signature=f"{v.type} {v.name}",
                    v1_location=None,
                    v2_location=_loc_for(v2_ast, v.name),
                    first_affected_slot=v2_slots_by_name.get(v.name),
                    extra={"type": v.type, "visibility": v.visibility},
                ))
                idx += 1

        # DELETEs (in v1 not v2)
        for v in v1_state_vars:
            if v.name not in v2_by_name:
                changes.append(Change(
                    id=f"c{idx:03d}",
                    op="DELETE",
                    node_kind="StateVariable",
                    node_name=v.name,
                    node_signature=f"{v.type} {v.name}",
                    v1_location=_loc_for(v1_ast, v.name),
                    v2_location=None,
                    first_affected_slot=v1_slots_by_name.get(v.name),
                    extra={"type": v.type, "visibility": v.visibility},
                ))
                idx += 1

        # UPDATEs (name same, type/visibility changed)
        for name, v1 in v1_by_name.items():
            v2 = v2_by_name.get(name)
            if v2 is None:
                continue
            if v1.type != v2.type or v1.visibility != v2.visibility:
                changes.append(Change(
                    id=f"c{idx:03d}",
                    op="UPDATE",
                    node_kind="StateVariable",
                    node_name=name,
                    node_signature=f"{v2.type} {name}",
                    v1_location=_loc_for(v1_ast, name),
                    v2_location=_loc_for(v2_ast, name),
                    first_affected_slot=v2_slots_by_name.get(name),
                    extra={"v1_type": v1.type, "v2_type": v2.type},
                ))
                idx += 1

        summary = {
            "insert": sum(1 for c in changes if c.op == "INSERT"),
            "delete": sum(1 for c in changes if c.op == "DELETE"),
            "update": sum(1 for c in changes if c.op == "UPDATE"),
        }
        return ASTDiffSet(changes=changes, summary=summary)


def _loc_for(ast, var_name: str) -> Location | None:
    for v in ast.state_variables_ordered:
        if v.name == var_name and v.source_mapping:
            sm = v.source_mapping
            filename = sm.filename.short if hasattr(sm.filename, "short") else str(sm.filename)
            return Location(file=filename, line=sm.lines[0] if sm.lines else 0)
    return None


def _slots_by_name(state_vars: list[StateVar]) -> dict[str, int]:
    """Return a mapping from variable name to the slot index it occupies."""
    mapping = compute_slot_mapping(state_vars)
    out: dict[str, int] = {}
    for slot, entry in mapping.items():
        out.setdefault(entry.name, slot)
    return out

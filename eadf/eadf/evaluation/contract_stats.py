"""Real ContractStats producer (Slither-backed) for EDA.

Run from the repo root so Slither resolves @openzeppelin remappings.
"""
from __future__ import annotations
from pathlib import Path

from .eda import ContractStats
from ..module2_ast_diff.slither_ast import build_ast, extract_state_variables
from ..module2_ast_diff.slot_mapper import compute_slot_mapping, packed_slots_present


def analyze_contract(path: Path) -> ContractStats:
    path = Path(path)
    loc = sum(1 for _ in path.read_text().splitlines())
    ast = build_ast(path)
    state_vars = extract_state_variables(ast)
    slot_map = compute_slot_mapping(state_vars)
    has_dynamic = any(getattr(v, "is_dynamic", False) for v in state_vars)
    return ContractStats(
        loc=loc,
        n_state_vars=len(state_vars),
        n_slots=len(slot_map),
        packed=packed_slots_present(state_vars),
        has_dynamic=has_dynamic,
    )

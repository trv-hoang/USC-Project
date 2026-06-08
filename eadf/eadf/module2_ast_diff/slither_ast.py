"""Wrap Slither so the rest of EADF speaks our SlitherAST dataclass."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

from slither import Slither
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.array_type import ArrayType

from ..models import StateVar


@dataclass
class SlitherAST:
    contract_name: str
    _contract: object   # underlying Slither Contract; opaque to callers

    @property
    def state_variables_ordered(self):
        return list(self._contract.state_variables_ordered)


def build_ast(source_path: Path) -> SlitherAST:
    """Compile the given .sol file with Slither and return the target contract.

    Real contracts (e.g. SecureLogicV1.sol) import many OpenZeppelin files;
    Slither.contracts then lists every imported contract too. We must select
    the one declared in the input file, not just contracts[-1] (which is
    non-deterministic and would silently analyse the wrong contract).

    Selection rule:
      1. Prefer the contract whose name matches source_path.stem (e.g.
         "SecureLogicV1" for "SecureLogicV1.sol"). This handles the common
         convention "one primary contract per file, named after the file".
      2. Otherwise prefer contracts whose source file matches source_path
         (i.e. declared in this file, not imported).
      3. If still multiple candidates, take the last one declared in the
         input file (Solidity convention: primary contract last).
      4. Raise if no contract matches.
    """
    sl = Slither(str(source_path))
    if not sl.contracts:
        raise RuntimeError(f"Slither found no contracts in {source_path}")

    stem = Path(source_path).stem
    # Rule 1
    by_name = [c for c in sl.contracts if c.name == stem]
    if by_name:
        return SlitherAST(contract_name=by_name[0].name, _contract=by_name[0])

    # Rule 2: contracts declared in the input file (not imported)
    src_abs = str(Path(source_path).resolve())
    declared_here = [
        c for c in sl.contracts
        if c.source_mapping
        and str(getattr(c.source_mapping.filename, "absolute", "")) == src_abs
    ]
    if declared_here:
        # Rule 3
        return SlitherAST(contract_name=declared_here[-1].name, _contract=declared_here[-1])

    # Rule 4
    raise RuntimeError(
        f"No contract in {source_path} matches the file stem '{stem}' and none "
        f"were declared in the input file. Found: {[c.name for c in sl.contracts]}"
    )


def extract_state_variables(ast: SlitherAST) -> list[StateVar]:
    out: list[StateVar] = []
    for v in ast.state_variables_ordered:
        canonical, is_dynamic = _canonical_type(v.type)
        out.append(StateVar(
            name=v.name,
            type=canonical,
            is_dynamic=is_dynamic,
            visibility=str(v.visibility),
        ))
    return out


def _canonical_type(t) -> tuple[str, bool]:
    if isinstance(t, ElementaryType):
        return (t.name, False)
    if isinstance(t, MappingType):
        return (f"mapping({t.type_from} => {t.type_to})", True)
    if isinstance(t, ArrayType):
        if t.length is None:
            return (f"{t.type}[]", True)
        return (f"{t.type}[{t.length_value}]", False)
    return (str(t), False)

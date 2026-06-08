"""Typed dataclasses for every stage's input/output.

Spec reference: §8 (stage data contracts).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal, Optional

# --- Module 1 outputs ---

@dataclass
class SourceMetadata:
    source_type: Literal["local", "etherscan"]
    v1: dict       # {"path_or_address": str, "label": str, "compiler": str}
    v2: dict
    fetched_at: str
    proxy_address: str
    upgrade_block: Optional[int]

@dataclass
class SourceBundle:
    v1_dir: Path
    v2_dir: Path
    metadata: SourceMetadata

# --- Module 2 outputs ---

@dataclass
class Location:
    file: str
    line: int
    col: Optional[int] = None
    function_name: Optional[str] = None

@dataclass
class StateVar:
    name: str
    type: str          # canonical type string from Slither (e.g. "uint256", "mapping(address => uint256)")
    is_dynamic: bool
    visibility: str

@dataclass
class SlotEntry:
    name: str
    type: str
    size: int          # bytes occupied within the slot
    offset: int        # byte offset within the slot

@dataclass
class Change:
    id: str
    op: Literal["INSERT", "DELETE", "UPDATE"]
    node_kind: Literal["StateVariable", "Function", "Modifier"]
    node_name: str
    node_signature: str
    v1_location: Optional[Location]
    v2_location: Optional[Location]
    first_affected_slot: Optional[int]
    extra: dict = field(default_factory=dict)

@dataclass
class ASTDiffSet:
    changes: list[Change]
    summary: dict      # {"insert": N, "delete": M, "update": K}

@dataclass
class SlotCollision:
    slot: int
    v1_var: str
    v2_var: str
    severity: Literal["Critical", "High", "Medium"]
    reason: str

@dataclass
class SlotDiff:
    v1_slots: dict[int, SlotEntry]
    v2_slots: dict[int, SlotEntry]
    collisions: list[SlotCollision]
    packed_slots_present: bool

# --- Module 3 outputs ---

@dataclass
class Finding:
    id: str
    detector_id: str
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    location: Location
    description: str
    extra: dict = field(default_factory=dict)

class UpgradeBehavior(str, Enum):
    INTRODUCE = "Introduce Vulnerability"
    FIX = "Fix Vulnerability"
    SMOOTH = "Smooth Upgrade"
    INVALID = "Invalid Upgrade"

# --- Module 4 outputs ---

@dataclass
class ConfidenceBreakdown:
    pos: float
    pattern: float
    semantic: float
    type: float
    slot: float

    @property
    def total(self) -> float:
        from .config import WEIGHTS
        return min(1.0,
                   WEIGHTS["pos"] * self.pos +
                   WEIGHTS["pattern"] * self.pattern +
                   WEIGHTS["semantic"] * self.semantic +
                   WEIGHTS["type"] * self.type +
                   WEIGHTS["slot"] * self.slot)

@dataclass
class MatchedPair:
    change_id: str
    vuln_id: str
    scores: ConfidenceBreakdown
    confidence: float
    root_cause: str

# --- Module 5 outputs ---

class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

@dataclass
class Report:
    proxy_address: str
    upgrade_block: Optional[int]
    impl_v1: str
    impl_v2: str
    upgrade_behavior: UpgradeBehavior
    storage_collision: dict
    vulnerabilities: dict   # {"v1": [...], "v2": [...], "introduced": [...], "fixed": [...]}
    matched_pairs: list[MatchedPair]
    risk_level: RiskLevel

# --- Stage runner ---

@dataclass
class StageError:
    stage: str
    where: str
    message: str

@dataclass
class StageResult:
    status: Literal["ok", "skipped", "failed"]
    output_path: Optional[Path]
    errors: list[StageError] = field(default_factory=list)
    fatal: Optional[StageError] = None

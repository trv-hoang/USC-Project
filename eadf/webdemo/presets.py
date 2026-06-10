"""Fixed demo presets, mapped to benchmark upgrade pairs."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# eadf/webdemo/presets.py -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH = REPO_ROOT / "eadf" / "benchmark"


@dataclass(frozen=True)
class Preset:
    id: str
    label: str
    scenario: str
    description: str
    pair_id: str
    category: str
    expected_behavior: str

    @property
    def v1(self) -> Path:
        return BENCH / self.category / self.pair_id / "v1.sol"

    @property
    def v2(self) -> Path:
        return BENCH / self.category / self.pair_id / "v2.sol"


PRESETS: list[Preset] = [
    Preset(
        id="storage_collision",
        label="Storage Collision",
        scenario="Kịch bản 1",
        description="Chèn biến mới trước biến cũ ở V2 → lệch storage slot, ghi đè dữ liệu.",
        pair_id="SC01",
        category="storage_collision",
        expected_behavior="Introduce Vulnerability",
    ),
    Preset(
        id="uninitialized",
        label="Uninitialized Implementation",
        scenario="Kịch bản 2",
        description="Implementation thiếu _disableInitializers() → attacker chiếm initialize().",
        pair_id="IN02",
        category="initialization",
        expected_behavior="Introduce Vulnerability",
    ),
    Preset(
        id="unauthorized",
        label="Unauthorized Upgrade",
        scenario="Kịch bản 3",
        description="_authorizeUpgrade thiếu onlyOwner → bất kỳ ai cũng nâng cấp được proxy.",
        pair_id="AU02",
        category="authorization",
        expected_behavior="Introduce Vulnerability",
    ),
    Preset(
        id="smooth",
        label="Smooth Upgrade (đối chứng)",
        scenario="Đối chứng",
        description="Nâng cấp an toàn (thêm biến ở cuối) → EADF không báo động giả.",
        pair_id="SM01",
        category="smooth",
        expected_behavior="Smooth Upgrade",
    ),
]


def get(preset_id: str) -> Optional[Preset]:
    for p in PRESETS:
        if p.id == preset_id:
            return p
    return None

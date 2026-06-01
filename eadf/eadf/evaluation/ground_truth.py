"""Benchmark ground-truth manifest loader (Approach A, offline).

The manifest (TOML) records, per V1->V2 pair: the intended upgrade behavior,
the detector_ids that SHOULD fire on each version (the oracle), and the proxy
pattern. Paths are resolved relative to the manifest file's directory.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

_VALID_BEHAVIORS = {
    "Introduce Vulnerability", "Fix Vulnerability",
    "Smooth Upgrade", "Invalid Upgrade",
}


@dataclass
class BenchmarkPair:
    id: str
    name: str
    category: str
    v1_path: Path
    v2_path: Path
    behavior: str
    vulns_v1: set[str]
    vulns_v2: set[str]
    proxy_pattern: str
    notes: str = ""


def load_manifest(path: Path) -> list[BenchmarkPair]:
    path = Path(path)
    data = tomllib.loads(path.read_text())
    base = path.parent
    pairs: list[BenchmarkPair] = []
    for raw in data.get("pair", []):
        behavior = raw["behavior"]
        if behavior not in _VALID_BEHAVIORS:
            raise ValueError(
                f"pair {raw.get('id')!r}: invalid behavior {behavior!r}; "
                f"must be one of {sorted(_VALID_BEHAVIORS)}"
            )
        pairs.append(BenchmarkPair(
            id=raw["id"],
            name=raw["name"],
            category=raw.get("category", ""),
            v1_path=(base / raw["v1"]).resolve(),
            v2_path=(base / raw["v2"]).resolve(),
            behavior=behavior,
            vulns_v1=set(raw.get("vulns_v1", [])),
            vulns_v2=set(raw.get("vulns_v2", [])),
            proxy_pattern=raw.get("proxy_pattern", "Unknown"),
            notes=raw.get("notes", ""),
        ))
    return pairs


def gt_vocabulary(pairs: list[BenchmarkPair]) -> set[str]:
    """Union of every detector_id used as ground truth across the benchmark."""
    vocab: set[str] = set()
    for p in pairs:
        vocab |= p.vulns_v1 | p.vulns_v2
    return vocab

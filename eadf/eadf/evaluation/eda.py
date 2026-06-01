"""Exploratory Data Analysis over the benchmark — fills SPEC §6.5.2 tables B.1-B.5.

Structural per-contract stats are produced by an injected `analyze_contract`
callable so this module stays unit-testable without Slither.
"""
from __future__ import annotations
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .ground_truth import BenchmarkPair


@dataclass
class ContractStats:
    loc: int
    n_state_vars: int
    n_slots: int
    packed: bool
    has_dynamic: bool


AnalyzeFn = Callable[[Path], ContractStats]


@dataclass
class EdaTables:
    behavior_dist: dict[str, int]
    proxy_dist: dict[str, int]
    vuln_dist: dict[str, int]
    loc_stats: dict[str, float]
    statevar_stats: dict[str, float]
    n_pairs: int

    def render_all(self) -> str:
        return "\n\n".join([
            self._render_behavior(),
            self._render_loc(),
            self._render_statevars(),
            self._render_vuln(),
            self._render_proxy(),
        ])

    def _render_behavior(self) -> str:
        order = ["Introduce Vulnerability", "Fix Vulnerability",
                 "Smooth Upgrade", "Invalid Upgrade"]
        total = sum(self.behavior_dist.values()) or 1
        rows = ["**B.1 — Phân bố hành vi nâng cấp** (theo Algorithm 5)", "",
                "| Hành vi nâng cấp | Số lượng | Tỷ lệ |", "|---|---|---|"]
        for b in order:
            c = self.behavior_dist.get(b, 0)
            rows.append(f"| {b} | {c} | {c / total * 100:.1f}% |")
        rows.append(f"| **Tổng** | {total} | 100% |")
        return "\n".join(rows)

    def _render_loc(self) -> str:
        s = self.loc_stats
        return "\n".join([
            "**B.2 — Thống kê quy mô mã nguồn (LOC mỗi implementation)**", "",
            "| Chỉ số | Giá trị |", "|---|---|",
            f"| Min | {s['min']:.0f} |",
            f"| Trung vị (median) | {s['median']:.1f} |",
            f"| Trung bình (mean) | {s['mean']:.1f} |",
            f"| Max | {s['max']:.0f} |",
            f"| Độ lệch chuẩn (std) | {s['std']:.1f} |",
        ])

    def _render_statevars(self) -> str:
        s = self.statevar_stats
        return "\n".join([
            "**B.3 — Thống kê biến trạng thái (state variables)**", "",
            "| Chỉ số | Giá trị |", "|---|---|",
            f"| Số biến trạng thái trung bình / contract | {s['mean_vars']:.2f} |",
            f"| Số storage slot trung bình / contract | {s['mean_slots']:.2f} |",
            f"| Tỷ lệ contract có packed slot | {s['packed_ratio'] * 100:.1f}% |",
            f"| Tỷ lệ contract dùng dynamic type | {s['dynamic_ratio'] * 100:.1f}% |",
        ])

    def _render_vuln(self) -> str:
        total = sum(self.vuln_dist.values()) or 1
        rows = ["**B.4 — Phân bố loại lỗ hổng** (theo `detector_id`, ground truth)", "",
                "| detector_id | Số lượng | Tỷ lệ |", "|---|---|---|"]
        for d, c in sorted(self.vuln_dist.items(), key=lambda kv: -kv[1]):
            rows.append(f"| `{d}` | {c} | {c / total * 100:.1f}% |")
        return "\n".join(rows)

    def _render_proxy(self) -> str:
        total = sum(self.proxy_dist.values()) or 1
        rows = ["**B.5 — Phân bố mẫu Proxy (proxy pattern)**", "",
                "| Proxy pattern | Số lượng | Tỷ lệ |", "|---|---|---|"]
        for d, c in sorted(self.proxy_dist.items(), key=lambda kv: -kv[1]):
            rows.append(f"| {d} | {c} | {c / total * 100:.1f}% |")
        rows.append(f"| **Tổng** | {total} | 100% |")
        return "\n".join(rows)


def compute_eda(pairs: list[BenchmarkPair], analyze_contract: AnalyzeFn) -> EdaTables:
    behavior_dist: dict[str, int] = {}
    proxy_dist: dict[str, int] = {}
    vuln_dist: dict[str, int] = {}
    locs: list[int] = []
    n_vars: list[int] = []
    n_slots: list[int] = []
    packed_flags: list[bool] = []
    dynamic_flags: list[bool] = []

    for p in pairs:
        behavior_dist[p.behavior] = behavior_dist.get(p.behavior, 0) + 1
        proxy_dist[p.proxy_pattern] = proxy_dist.get(p.proxy_pattern, 0) + 1
        for d in (p.vulns_v1 | p.vulns_v2):
            vuln_dist[d] = vuln_dist.get(d, 0) + 1
        for path in (p.v1_path, p.v2_path):
            cs = analyze_contract(path)
            locs.append(cs.loc)
            n_vars.append(cs.n_state_vars)
            n_slots.append(cs.n_slots)
            packed_flags.append(cs.packed)
            dynamic_flags.append(cs.has_dynamic)

    def _stats(xs):
        return {
            "min": min(xs) if xs else 0,
            "max": max(xs) if xs else 0,
            "mean": statistics.fmean(xs) if xs else 0.0,
            "median": statistics.median(xs) if xs else 0.0,
            "std": statistics.pstdev(xs) if len(xs) > 1 else 0.0,
        }

    n = len(packed_flags) or 1
    statevar_stats = {
        "mean_vars": statistics.fmean(n_vars) if n_vars else 0.0,
        "mean_slots": statistics.fmean(n_slots) if n_slots else 0.0,
        "packed_ratio": sum(packed_flags) / n,
        "dynamic_ratio": sum(dynamic_flags) / n,
    }
    return EdaTables(
        behavior_dist=behavior_dist,
        proxy_dist=proxy_dist,
        vuln_dist=vuln_dist,
        loc_stats=_stats(locs),
        statevar_stats=statevar_stats,
        n_pairs=len(pairs),
    )

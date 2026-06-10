"""Extract the real source of EADF's core algorithms for the demo's code tab,
paired with the pseudocode from the thesis (SPEC §5.4 / §5.7) so the audience can
see the spec ↔ implementation mapping side by side.

Uses `ast` to slice named functions out of the actual package files — no import
is executed, so heavy/lazy module side effects (e.g. loading data tables) never run.
"""
from __future__ import annotations

import ast
from pathlib import Path

# webdemo/ -> parents[1] == repo/eadf ; package source lives in repo/eadf/eadf
PKG = Path(__file__).resolve().parents[1] / "eadf"

PSEUDO_COMPARE_SLOTS = """Algorithm 3 — CompareSlotMappings  (Storage Slot Differential)
Input : M1, M2 — ánh xạ slot của V1, V2
Output: collisions — (slot, v1_var, v2_var, severity, reason)

 1: collisions ← []
 2: for s in sort(keys(M1) ∪ keys(M2)):
 3:     a ← M1[s];  b ← M2[s]
 4:     if a = ⊥ or b = ⊥: continue            # slot chỉ có ở 1 phiên bản
 5:     if (a.name, a.type) ≠ (b.name, b.type):  # cùng slot, khác biến → collision
 6:         (sev, reason) ← ClassifySeverity(a, b, s)
 7:         thêm (s, a.name, b.name, sev, reason) vào collisions
 8: return collisions

ClassifySeverity(a, b, s):                      # match đầu tiên thắng
 9:  if a.name ~ /owner|implementation|admin|proxy/i:        return Critical
10:  if s = 0 and a.type ∈ {address, uint256, bytes32}:      return Critical
11:  if a.type ~ "mapping(" or a.name ~ /balance|allow/i:    return High
12:  if s = 0:                                               return High
13:  return Medium"""

PSEUDO_CONFIDENCE = """Algorithm 4 — ComputeConfidence  (5-dimensional scoring)
Input : change, vuln, slot_diff, src_v2_lines
Output: confidence ∈ [0, 1]
w = (pos .25, pattern .20, semantic .25, type .15, slot .15)

 1: d ← |change.line − vuln.line|
 2: S_pos ← 1.0 nếu d=0; .8 nếu d≤2; .5 nếu d≤5; .2 nếu d≤10; else .1
 3: ctx ← src_v2_lines[line_c−5 .. line_c+5]
 4: S_pattern ← min(1, .1 × |{kw ∈ Keywords(vuln.detector) : kw ∈ ctx}|)
 5: S_semantic ← min(1, .30 f1 + .20 f2 + .15 f3 + .15 f4 + .10 f5 + .10 f6)
 6: S_type ← OpVulnMap[(change.op, change.node_kind)][vuln.detector]
 7: S_slot ← CalcSlotScore(change, vuln, slot_diff)   # chiều mới của đề tài
 8: confidence ← w.pos·S_pos + w.pattern·S_pattern + w.semantic·S_semantic
 9:               + w.type·S_type + w.slot·S_slot
10: return confidence"""

PSEUDO_DETECTOR = """Custom Detector — Storage Collision Cross-Version (SPEC §5.4)
Input : slot_diff (từ Module 2)
Output: findings — danh sách lỗ hổng chuẩn hóa

 1: findings ← []
 2: for collision in slot_diff.collisions:
 3:     findings.append({
 4:         "detector_id": "storage-collision-cross-version",
 5:         "severity":    collision.severity,     # Critical/High/Medium
 6:         "affected_slots": collision.slots,
 7:         "v1_variable": collision.var_v1,
 8:         "v2_variable": collision.var_v2,
 9:         "location":    collision.location })
10: return findings"""

# (display_name, source_relpath, function_name, pseudocode, module_tag)
SPECS = [
    ("CompareSlotMappings", "module2_ast_diff/slot_mapper.py", "diff_slot_maps",
     PSEUDO_COMPARE_SLOTS, "Module 2"),
    ("ComputeConfidence (5 chiều)", "module4_matcher/confidence_scorer.py", "compute_confidence",
     PSEUDO_CONFIDENCE, "Module 4"),
    ("StorageCollisionDetector", "module3_vuln_detector/storage_collision_detector.py",
     "detect_storage_collision", PSEUDO_DETECTOR, "Module 3"),
]


def _extract(path: Path, func: str) -> str:
    text = path.read_text()
    tree = ast.parse(text)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func:
            lines = text.splitlines()
            return "\n".join(lines[node.lineno - 1: node.end_lineno])
    raise ValueError(f"function {func} not found in {path}")


def algorithms() -> list[dict]:
    return [
        {
            "name": name,
            "file": f"eadf/{rel}",
            "code": _extract(PKG / rel, fn),
            "pseudo": pseudo,
            "module": module,
        }
        for name, rel, fn, pseudo, module in SPECS
    ]

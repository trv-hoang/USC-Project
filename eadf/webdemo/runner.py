"""Run the real EADF pipeline for the web demo and assemble a UI payload."""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FOUNDRY_BIN = Path.home() / ".foundry" / "bin"
EADF_BIN = REPO_ROOT / "eadf" / ".venv" / "bin" / "eadf"

_STAGE_MARK = "Stage "  # lines look like "Stage 2 complete: ..."


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def assemble_payload(workdir: Path, preset_id: str, label: str, source: str = "live") -> dict:
    """Combine stage5 report + stage2 slot diff + checklist into one UI payload.

    Raises FileNotFoundError if any required stage output is missing.
    """
    workdir = Path(workdir)
    report = _read_json(workdir / "stage5_report.json")
    slot = _read_json(workdir / "stage2_slot_diff.json")
    checklist = (workdir / "checklist.md").read_text()

    return {
        "preset": preset_id,
        "label": label,
        "behavior": report["upgrade_behavior"],
        "risk_level": report["risk_level"],
        "impl_v1": report.get("impl_v1", ""),
        "impl_v2": report.get("impl_v2", ""),
        "storage": {
            "v1_slots": slot["v1_slots"],
            "v2_slots": slot["v2_slots"],
            "collisions": slot["collisions"],
            "packed_slots_present": slot.get("packed_slots_present", False),
            "summary": report.get("storage_collision", {}),
        },
        "findings": report["vulnerabilities"],
        "matched_pairs": report["matched_pairs"],
        "checklist_md": checklist,
        "source": source,
    }


def build_env(work_root: Path) -> dict:
    env = os.environ.copy()
    env["PATH"] = str(FOUNDRY_BIN) + os.pathsep + env.get("PATH", "")
    env["EADF_WORK_ROOT"] = str(work_root)
    return env


def _run_dir(work_root: Path, run_id: str) -> Path:
    return Path(work_root) / run_id


_STAGE_ACTION = {
    1: "M1 · thu thập & chuẩn hóa source 2 phiên bản",
    2: "M2 · dựng AST + tính storage slot, so V1↔V2",
    3: "M3 · Slither + custom detectors + phân loại hành vi",
    4: "M4 · ánh xạ thay đổi↔lỗ hổng (confidence 5 chiều)",
    5: "M5 · tổng hợp rủi ro + sinh report/checklist",
}


def _stage_detail(n: int, run_dir: Path) -> list[str]:
    """Read the artifact a stage just produced and describe it (real data)."""
    rd = Path(run_dir)
    out: list[str] = []
    try:
        if n == 1:
            meta = json.loads((rd / "stage1_sources" / "metadata.json").read_text())
            v1 = Path(meta.get("v1", {}).get("path_or_address", "")).name
            v2 = Path(meta.get("v2", {}).get("path_or_address", "")).name
            out.append(f"   -> nạp V1={v1} · V2={v2}")
        elif n == 2:
            slot = json.loads((rd / "stage2_slot_diff.json").read_text())
            out.append(f"   -> storage slots: V1={len(slot.get('v1_slots', {}))}, "
                       f"V2={len(slot.get('v2_slots', {}))}")
            try:
                ast = json.loads((rd / "stage2_ast_diff.json").read_text())
                out.append(f"   -> AST changes (INSERT/DELETE/UPDATE/MOVE): {len(ast.get('changes', []))}")
            except FileNotFoundError:
                pass
            cols = slot.get("collisions", [])
            if cols:
                for c in cols:
                    out.append(f"   -> COLLISION @ slot {c['slot']}: {c['v1_var']} -> {c['v2_var']} [{c['severity']}]")
            else:
                out.append("   -> không có collision")
        elif n == 3:
            v = json.loads((rd / "stage3_vulnerabilities.json").read_text())
            out.append(f"   -> findings: V1={len(v.get('v1', []))}, V2={len(v.get('v2', []))} "
                       f"· behavior={v.get('upgrade_behavior', '?')}")
            for f in v.get("v2", []):
                out.append(f"   -> V2 finding: {f['detector_id']} [{f['severity']}]")
        elif n == 4:
            mp = json.loads((rd / "stage4_matched_pairs.json").read_text())
            pairs = mp.get("pairs", [])
            if pairs:
                top = max(pairs, key=lambda p: p.get("confidence", 0))
                out.append(f"   -> matched {len(pairs)} cặp · top confidence={top.get('confidence', 0):.2f}")
            else:
                out.append("   -> 0 cặp ánh xạ (không có thay đổi khớp lỗ hổng)")
        elif n == 5:
            r = json.loads((rd / "stage5_report.json").read_text())
            out.append(f"   -> risk_level={r.get('risk_level', '?')} · report.json + checklist.md đã sinh")
    except (FileNotFoundError, KeyError, ValueError):
        pass
    return out


def stream_analysis(preset, work_root: Path):
    """Yield {'type':'stage','stage':N} as each EADF stage finishes, then
    {'type':'result','payload':...}. Raises on non-zero exit (caller handles fallback)."""
    run_id = f"web_{int(time.time() * 1000)}"
    cmd = [
        str(EADF_BIN), "run",
        "--local-v1", str(preset.v1),
        "--local-v2", str(preset.v2),
        "--run-id", run_id,
    ]
    # Surface the command so the audience sees the real invocation (paths shown
    # relative to the repo root for readability; the real call uses absolute paths).
    def _rel(x: str) -> str:
        try:
            return str(Path(x).relative_to(REPO_ROOT))
        except ValueError:
            return Path(x).name if x == str(EADF_BIN) else x
    yield {"type": "log", "line": "$ eadf run --local-v1 " + _rel(str(preset.v1))
           + " --local-v2 " + _rel(str(preset.v2))}
    t0 = time.time()
    run_dir = _run_dir(work_root, run_id)
    proc = subprocess.Popen(
        cmd, cwd=str(REPO_ROOT), env=build_env(work_root),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    for line in proc.stdout:
        s = line.strip()
        if not s:
            continue
        if s.startswith(_STAGE_MARK) and "complete" in s:
            try:
                n = int(s.split()[1])
            except (IndexError, ValueError):
                yield {"type": "log", "line": s}
                continue
            # shorten the long temp path to filenames for readability
            head, _, paths = s.partition(":")
            names = ", ".join(Path(x.strip()).name for x in paths.split(",") if x.strip())
            yield {"type": "log", "line": f"{head}: {names}" if names else s}
            yield {"type": "stage", "stage": n}
            yield {"type": "log", "line": f"  [{_STAGE_ACTION.get(n, '')}]  ({time.time() - t0:.1f}s)"}
            for detail in _stage_detail(n, run_dir):
                yield {"type": "log", "line": detail}
        else:
            yield {"type": "log", "line": s}
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"eadf run failed (exit {proc.returncode})")
    yield {"type": "log", "line": f"  ⏱ hoàn tất pipeline trong {time.time() - t0:.1f}s"}
    payload = assemble_payload(run_dir, preset.id, preset.label, source="live")
    yield {"type": "result", "payload": payload}


def run_analysis(preset, work_root: Path) -> dict:
    """Blocking full run → payload (used by prewarm)."""
    result = None
    for event in stream_analysis(preset, work_root):
        if event["type"] == "result":
            result = event["payload"]
    assert result is not None
    return result

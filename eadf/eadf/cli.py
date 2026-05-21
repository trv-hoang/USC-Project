"""EADF CLI entry point.

Each subcommand currently raises NotImplementedError; later phases wire each
to its module. Keeping the surface stable from day 1 means downstream tests
and docs don't churn.
"""
from pathlib import Path
import typer

app = typer.Typer(help="EADF — Evolution-Aware Detection Framework")

@app.command()
def run(
    proxy: str = typer.Option(None, "--proxy"),
    local_v1: Path = typer.Option(None, "--local-v1"),
    local_v2: Path = typer.Option(None, "--local-v2"),
    run_id: str = typer.Option(None, "--run-id"),
    from_stage: int = typer.Option(1, "--from-stage"),
):
    """Run all five EADF stages: collect → diff → detect → match → report."""
    import os
    from .workdir import WorkDir

    # Validate that we have enough args to run at least collect
    if from_stage <= 1 and not (proxy or (local_v1 and local_v2)):
        typer.echo(
            "Provide either --proxy or both --local-v1 and --local-v2", err=True
        )
        raise typer.Exit(code=2)

    # Determine the run_id up front so each stage sees the same one.
    if run_id is None:
        wd_tmp = WorkDir(root=Path(os.environ.get("EADF_WORK_ROOT", "work")))
        run_id = wd_tmp.run_id

    if from_stage <= 1:
        collect(proxy=proxy, local_v1=local_v1, local_v2=local_v2, run_id=run_id)
    if from_stage <= 2:
        diff(run_id=run_id)
    if from_stage <= 3:
        detect(run_id=run_id)
    if from_stage <= 4:
        match_cmd(run_id=run_id, config=None)
    if from_stage <= 5:
        report(run_id=run_id)

    typer.echo(f"Pipeline complete: run_id={run_id}")

@app.command()
def collect(
    proxy: str = typer.Option(None, "--proxy"),
    local_v1: Path = typer.Option(None, "--local-v1"),
    local_v2: Path = typer.Option(None, "--local-v2"),
    run_id: str = typer.Option(None, "--run-id"),
):
    """Stage 1 — Fetch sources (local or Etherscan)."""
    import os
    from .workdir import WorkDir
    from .module1_collector.local_source import LocalSource

    root = Path(os.environ.get("EADF_WORK_ROOT", "work"))
    wd = WorkDir(root=root, run_id=run_id)
    wd.ensure()
    stage1 = wd.stage_dir(1)
    stage1.mkdir(parents=True, exist_ok=True)

    if local_v1 and local_v2:
        provider = LocalSource(v1_path=local_v1, v2_path=local_v2)
    elif proxy:
        raise typer.Exit(code=2)  # Etherscan path lands in Phase 9
    else:
        typer.echo("Provide either --proxy or both --local-v1 and --local-v2", err=True)
        raise typer.Exit(code=2)

    provider.fetch(stage1)
    typer.echo(f"Stage 1 complete: {stage1}")

@app.command()
def diff(run_id: str = typer.Option(..., "--run-id")):
    """Stage 2 — AST diff + storage slot diff."""
    import json as _json
    import os
    from .workdir import WorkDir
    from .module2_ast_diff.slither_ast import build_ast, extract_state_variables
    from .module2_ast_diff.simple_differ import SimpleASTDiffer
    from .module2_ast_diff.slot_mapper import compute_slot_mapping, diff_slot_maps, packed_slots_present

    root = Path(os.environ.get("EADF_WORK_ROOT", "work"))
    wd = WorkDir(root=root, run_id=run_id)
    stage1 = wd.stage_dir(1)

    # Prefer original source paths recorded in metadata (so Slither can resolve
    # imports from the project root). Fall back to the copied stage1 files.
    metadata_path = stage1 / "metadata.json"
    if metadata_path.exists():
        meta = _json.loads(metadata_path.read_text())
        v1_src = Path(meta["v1"]["path_or_address"])
        v2_src = Path(meta["v2"]["path_or_address"])
        # Validate that the original files still exist; fall back if they don't
        if not v1_src.exists() or not v2_src.exists():
            v1_files = list((stage1 / "v1").glob("*.sol"))
            v2_files = list((stage1 / "v2").glob("*.sol"))
            if not v1_files or not v2_files:
                typer.echo("Missing v1 or v2 .sol in stage1", err=True)
                raise typer.Exit(code=1)
            v1_src, v2_src = v1_files[0], v2_files[0]
    else:
        v1_files = list((stage1 / "v1").glob("*.sol"))
        v2_files = list((stage1 / "v2").glob("*.sol"))
        if not v1_files or not v2_files:
            typer.echo("Missing v1 or v2 .sol in stage1", err=True)
            raise typer.Exit(code=1)
        v1_src, v2_src = v1_files[0], v2_files[0]

    ast_v1 = build_ast(v1_src)
    ast_v2 = build_ast(v2_src)
    v1_vars = extract_state_variables(ast_v1)
    v2_vars = extract_state_variables(ast_v2)

    ast_diff = SimpleASTDiffer().diff(ast_v1, ast_v2, v1_state_vars=v1_vars, v2_state_vars=v2_vars)
    slot_map_v1 = compute_slot_mapping(v1_vars)
    slot_map_v2 = compute_slot_mapping(v2_vars)
    slot_diff = diff_slot_maps(slot_map_v1, slot_map_v2)
    slot_diff.packed_slots_present = packed_slots_present(v1_vars) or packed_slots_present(v2_vars)

    wd.write_json(wd.stage_path(2, "ast_diff.json"), ast_diff)
    wd.write_json(wd.stage_path(2, "slot_diff.json"), slot_diff)
    typer.echo(f"Stage 2 complete: {wd.stage_path(2, 'ast_diff.json')}")

@app.command()
def detect(run_id: str = typer.Option(..., "--run-id")):
    """Stage 3 — Vulnerability detection."""
    import os, json
    from .workdir import WorkDir
    from .models import SlotDiff, SlotCollision, SlotEntry
    from .module2_ast_diff.slither_ast import build_ast
    from .module3_vuln_detector.slither_runner import run_slither
    from .module3_vuln_detector.storage_collision_detector import detect_storage_collision
    from .module3_vuln_detector.unauthorized_upgrade_detector import detect_missing_upgrade_authorization
    from .module3_vuln_detector.disable_initializers_detector import detect_missing_disable_initializers
    from .module3_vuln_detector.behavior_classifier import classify_behavior

    root = Path(os.environ.get("EADF_WORK_ROOT", "work"))
    wd = WorkDir(root=root, run_id=run_id)
    stage1 = wd.stage_dir(1)

    # Prefer original source paths from metadata (so Slither resolves imports
    # from the project root). Mirror the same logic used in `diff`.
    metadata_path = stage1 / "metadata.json"
    if metadata_path.exists():
        meta = json.loads(metadata_path.read_text())
        v1_src = Path(meta["v1"]["path_or_address"])
        v2_src = Path(meta["v2"]["path_or_address"])
        if not v1_src.exists() or not v2_src.exists():
            v1_files = list((stage1 / "v1").glob("*.sol"))
            v2_files = list((stage1 / "v2").glob("*.sol"))
            if not v1_files or not v2_files:
                typer.echo("Missing v1 or v2 .sol in stage1", err=True)
                raise typer.Exit(code=1)
            v1_src, v2_src = v1_files[0], v2_files[0]
    else:
        v1_files = list((stage1 / "v1").glob("*.sol"))
        v2_files = list((stage1 / "v2").glob("*.sol"))
        if not v1_files or not v2_files:
            typer.echo("Missing v1 or v2 .sol in stage1", err=True)
            raise typer.Exit(code=1)
        v1_src, v2_src = v1_files[0], v2_files[0]

    # Precondition: stage 2 must exist (diff was run)
    slot_diff_path = wd.stage_path(2, "slot_diff.json")
    if not slot_diff_path.exists():
        typer.echo(f"Stage 2 output missing at {slot_diff_path}. Run 'eadf diff --run-id {run_id}' first.", err=True)
        raise typer.Exit(code=1)

    # Stock Slither detectors on both versions
    v1_findings = run_slither(v1_src)
    v2_findings = run_slither(v2_src)

    # Custom detector: missing-upgrade-authorization (per-version AST inspection)
    v1_findings.extend(detect_missing_upgrade_authorization(build_ast(v1_src), source_file=v1_src.name))
    v2_findings.extend(detect_missing_upgrade_authorization(build_ast(v2_src), source_file=v2_src.name))

    # Custom detector: missing-disable-initializers (per-version AST inspection)
    v1_findings.extend(detect_missing_disable_initializers(build_ast(v1_src), source_file=v1_src.name))
    v2_findings.extend(detect_missing_disable_initializers(build_ast(v2_src), source_file=v2_src.name))

    # Custom detector: storage-collision-cross-version (consumes Stage 2 slot diff)
    slot_diff_raw = json.loads(slot_diff_path.read_text())
    collisions = [SlotCollision(**c) for c in slot_diff_raw.get("collisions", [])]
    slot_diff = SlotDiff(
        v1_slots={int(k): SlotEntry(**v) for k, v in slot_diff_raw["v1_slots"].items()},
        v2_slots={int(k): SlotEntry(**v) for k, v in slot_diff_raw["v2_slots"].items()},
        collisions=collisions,
        packed_slots_present=slot_diff_raw.get("packed_slots_present", False),
    )
    v2_line_lookup = _v2_line_lookup(wd)
    v2_findings.extend(detect_storage_collision(slot_diff, source_file=v2_src.name, v2_line_lookup=v2_line_lookup))

    # Renumber all findings into v{NNN} per-version (resolves the ID-space note;
    # detector-emitted ids like ua{NNN} / sc{NNN} are transient inside the module).
    _renumber(v1_findings)
    _renumber(v2_findings)

    behavior = classify_behavior(v1_findings, v2_findings)
    payload = {
        "v1": [_finding_to_dict(f) for f in v1_findings],
        "v2": [_finding_to_dict(f) for f in v2_findings],
        "upgrade_behavior": behavior.value,
    }
    wd.write_json(wd.stage_path(3, "vulnerabilities.json"), payload)
    typer.echo(f"Stage 3 complete: {wd.stage_path(3, 'vulnerabilities.json')}")


def _finding_to_dict(f):
    from dataclasses import asdict
    return asdict(f)


def _renumber(findings):
    """Normalize detector-emitted ids (sc{NNN}, ua{NNN}, v{NNN}) into a single
    v{NNN} sequence per version, in emission order. Spec §8.3 contract.
    """
    for i, f in enumerate(findings, start=1):
        f.id = f"v{i:03d}"
    return findings


def _v2_line_lookup(wd) -> dict[str, int]:
    """Read line numbers from stage2_ast_diff.json for INSERT/UPDATE state vars."""
    import json
    ast_diff = json.loads(wd.stage_path(2, "ast_diff.json").read_text())
    out = {}
    for c in ast_diff.get("changes", []):
        if c.get("v2_location"):
            out[c["node_name"]] = c["v2_location"]["line"]
    return out


def _change_from_dict(d) -> "Change":
    from .models import Change, Location
    def _loc(x): return Location(**x) if x else None
    return Change(
        id=d["id"], op=d["op"], node_kind=d["node_kind"],
        node_name=d["node_name"], node_signature=d["node_signature"],
        v1_location=_loc(d.get("v1_location")), v2_location=_loc(d.get("v2_location")),
        first_affected_slot=d.get("first_affected_slot"),
        extra=d.get("extra", {}),
    )


def _finding_from_dict(d) -> "Finding":
    from .models import Finding, Location
    return Finding(
        id=d["id"], detector_id=d["detector_id"], severity=d["severity"],
        location=Location(**d["location"]), description=d.get("description", ""),
        extra=d.get("extra", {}),
    )


def _matched_pair_to_dict(p) -> dict:
    from dataclasses import asdict
    return asdict(p)


@app.command("match")
def match_cmd(
    run_id: str = typer.Option(..., "--run-id"),
    config: Path = typer.Option(None, "--config"),
):
    """Stage 4 — Match changes to vulnerabilities."""
    import os, json
    from .config import WEIGHTS, CONFIDENCE_THRESHOLD
    from .workdir import WorkDir
    from .models import (
        ASTDiffSet, Change, Location, SlotDiff, SlotCollision, SlotEntry,
        Finding,
    )
    from .module4_matcher.confidence_scorer import match as compute_matches

    root = Path(os.environ.get("EADF_WORK_ROOT", "work"))
    wd = WorkDir(root=root, run_id=run_id)

    # Precondition checks
    ast_diff_path = wd.stage_path(2, "ast_diff.json")
    slot_diff_path = wd.stage_path(2, "slot_diff.json")
    vuln_path = wd.stage_path(3, "vulnerabilities.json")
    for p, prev_cmd in [
        (ast_diff_path, "diff"), (slot_diff_path, "diff"), (vuln_path, "detect"),
    ]:
        if not p.exists():
            typer.echo(f"Missing {p}. Run 'eadf {prev_cmd} --run-id {run_id}' first.", err=True)
            raise typer.Exit(code=1)

    # Reconstruct dataclasses from JSON
    ast_diff_raw = json.loads(ast_diff_path.read_text())
    ast_diff = ASTDiffSet(
        changes=[_change_from_dict(c) for c in ast_diff_raw["changes"]],
        summary=ast_diff_raw.get("summary", {}),
    )

    slot_diff_raw = json.loads(slot_diff_path.read_text())
    slot_diff = SlotDiff(
        v1_slots={int(k): SlotEntry(**v) for k, v in slot_diff_raw["v1_slots"].items()},
        v2_slots={int(k): SlotEntry(**v) for k, v in slot_diff_raw["v2_slots"].items()},
        collisions=[SlotCollision(**c) for c in slot_diff_raw.get("collisions", [])],
        packed_slots_present=slot_diff_raw.get("packed_slots_present", False),
    )

    vuln_raw = json.loads(vuln_path.read_text())
    v2_findings = [_finding_from_dict(f) for f in vuln_raw.get("v2", [])]

    # Load V2 source text for context-window keyword scoring
    v2_source_lines: list[str] = []
    stage1 = wd.stage_dir(1)
    v2_files = list((stage1 / "v2").glob("*.sol"))
    if v2_files:
        v2_source_lines = v2_files[0].read_text().splitlines()

    pairs = compute_matches(ast_diff, v2_findings, slot_diff, v2_source_lines,
                            threshold=CONFIDENCE_THRESHOLD)

    matched_change_ids = {p.change_id for p in pairs}
    matched_vuln_ids = {p.vuln_id for p in pairs}
    unmatched_changes = [c.id for c in ast_diff.changes if c.id not in matched_change_ids]
    unmatched_vulns = [f.id for f in v2_findings if f.id not in matched_vuln_ids]

    payload = {
        "threshold": CONFIDENCE_THRESHOLD,
        "weights": dict(WEIGHTS),
        "pairs": [_matched_pair_to_dict(p) for p in pairs],
        "unmatched_changes": unmatched_changes,
        "unmatched_vulns": unmatched_vulns,
    }
    wd.write_json(wd.stage_path(4, "matched_pairs.json"), payload)
    typer.echo(f"Stage 4 complete: {wd.stage_path(4, 'matched_pairs.json')}")

@app.command()
def report(run_id: str = typer.Option(..., "--run-id")):
    """Stage 5 — Render JSON report + Markdown checklist."""
    import os
    from .workdir import WorkDir
    from .module5_reporter.json_reporter import build_report, dump_report
    from .module5_reporter.checklist_generator import render_checklist

    root = Path(os.environ.get("EADF_WORK_ROOT", "work"))
    wd = WorkDir(root=root, run_id=run_id)

    # Preconditions
    for stage_n, filename in [(4, "matched_pairs.json"), (3, "vulnerabilities.json"), (2, "slot_diff.json")]:
        p = wd.stage_path(stage_n, filename)
        if not p.exists():
            typer.echo(f"Missing {p}. Run earlier stages first.", err=True)
            raise typer.Exit(code=1)

    rpt = build_report(wd.base)
    report_path = wd.stage_path(5, "report.json")
    dump_report(rpt, report_path)

    checklist_md = render_checklist(rpt)
    checklist_path = wd.base / "checklist.md"
    checklist_path.write_text(checklist_md)

    typer.echo(f"Stage 5 complete: {report_path}, {checklist_path}")


@app.command("list")
def list_cmd():
    """List run IDs in the work directory."""
    import os
    root = Path(os.environ.get("EADF_WORK_ROOT", "work"))
    if not root.exists():
        typer.echo("(no work directory yet)")
        return
    run_ids = sorted(p.name for p in root.iterdir() if p.is_dir())
    if not run_ids:
        typer.echo("(no runs yet)")
        return
    for run_id in run_ids:
        typer.echo(run_id)


@app.command()
def show(run_id: str):
    """Show summary of a run's report."""
    import os
    import json as _json
    root = Path(os.environ.get("EADF_WORK_ROOT", "work"))
    report_path = root / run_id / "stage5_report.json"
    if not report_path.exists():
        typer.echo(f"No report found at {report_path}. Run 'eadf report --run-id {run_id}' first.", err=True)
        raise typer.Exit(code=1)
    report = _json.loads(report_path.read_text())
    typer.echo(f"Run: {run_id}")
    typer.echo(f"  Proxy:             {report.get('proxy_address')}")
    typer.echo(f"  V1 → V2:           {report.get('impl_v1')} → {report.get('impl_v2')}")
    typer.echo(f"  Upgrade behavior:  {report.get('upgrade_behavior')}")
    typer.echo(f"  Risk level:        {report.get('risk_level')}")
    sc = report.get("storage_collision", {})
    if sc.get("detected"):
        typer.echo(f"  Storage collision: {sc.get('severity')} at slot(s) {sc.get('affected_slots')}")
    pairs = report.get("matched_pairs", [])
    typer.echo(f"  Matched pairs:     {len(pairs)}")
    for p in pairs:
        typer.echo(f"    {p['change_id']} ↔ {p['vuln_id']} conf={p['confidence']}")

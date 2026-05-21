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
    """Run all five EADF stages."""
    raise NotImplementedError("wired in Phase 8")

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

@app.command("match")
def match_cmd(
    run_id: str = typer.Option(..., "--run-id"),
    config: Path = typer.Option(None, "--config"),
):
    """Stage 4 — Match changes to vulnerabilities."""
    raise NotImplementedError("wired in Phase 6")

@app.command()
def report(run_id: str = typer.Option(..., "--run-id")):
    """Stage 5 — Render JSON report + Markdown checklist."""
    raise NotImplementedError("wired in Phase 7")

@app.command("list")
def list_cmd():
    """List run IDs in work/."""
    raise NotImplementedError("wired in Phase 8")

@app.command()
def show(run_id: str):
    """Show summary of a run's report."""
    raise NotImplementedError("wired in Phase 8")

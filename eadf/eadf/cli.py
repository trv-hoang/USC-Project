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
    """Stage 2 — Compute AST diff + storage slot diff."""
    raise NotImplementedError("wired in Phase 4")

@app.command()
def detect(run_id: str = typer.Option(..., "--run-id")):
    """Stage 3 — Run vulnerability detectors."""
    raise NotImplementedError("wired in Phase 5")

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

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
    raise NotImplementedError("wired in Phase 3")

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

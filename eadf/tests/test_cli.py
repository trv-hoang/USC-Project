# eadf/tests/test_cli.py
from typer.testing import CliRunner
from eadf.cli import app

runner = CliRunner()

def test_help_works():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "EADF" in result.stdout or "eadf" in result.stdout.lower()

def test_subcommands_registered():
    result = runner.invoke(app, ["--help"])
    for cmd in ["run", "collect", "diff", "detect", "match", "report", "list", "show"]:
        assert cmd in result.stdout

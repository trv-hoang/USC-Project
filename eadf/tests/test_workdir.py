# eadf/tests/test_workdir.py
import json
from pathlib import Path
from eadf.workdir import WorkDir

def test_creates_run_directory(tmp_path):
    wd = WorkDir(root=tmp_path, run_id="local_demo")
    wd.ensure()
    assert (tmp_path / "local_demo").is_dir()

def test_stage_paths(tmp_path):
    wd = WorkDir(root=tmp_path, run_id="r1")
    wd.ensure()
    assert wd.stage_dir(1) == tmp_path / "r1" / "stage1_sources"
    assert wd.stage_path(2, "ast_diff.json") == tmp_path / "r1" / "stage2_ast_diff.json"

def test_atomic_write_json(tmp_path):
    wd = WorkDir(root=tmp_path, run_id="r1")
    wd.ensure()
    wd.write_json(wd.stage_path(2, "ast_diff.json"), {"changes": []})
    loaded = json.loads(wd.stage_path(2, "ast_diff.json").read_text())
    assert loaded == {"changes": []}

def test_auto_run_id_when_unspecified(tmp_path):
    wd = WorkDir(root=tmp_path, run_id=None)
    assert wd.run_id.startswith("run_")

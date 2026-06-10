from pathlib import Path

import pytest

import runner

FIX = Path(__file__).resolve().parent / "fixtures" / "workdir"


def test_assemble_payload_reads_all_stage_files():
    payload = runner.assemble_payload(FIX, preset_id="storage_collision", label="Storage Collision")
    assert payload["preset"] == "storage_collision"
    assert payload["behavior"] == "Introduce Vulnerability"
    assert payload["risk_level"] == "Critical"
    # storage slot differential
    assert payload["storage"]["v1_slots"]["0"]["name"] == "value"
    assert payload["storage"]["v2_slots"]["0"]["name"] == "collisionVar"
    assert payload["storage"]["collisions"][0]["severity"] == "Critical"
    # findings
    assert len(payload["findings"]["introduced"]) == 1
    assert payload["findings"]["fixed"] == []
    # matched pairs with 5-dim scores
    mp = payload["matched_pairs"][0]
    assert mp["confidence"] == 0.7825
    assert set(mp["scores"]) == {"pos", "pattern", "semantic", "type", "slot"}
    assert "root_cause" in mp
    # checklist + source flag
    assert payload["checklist_md"].startswith("## EADF Security Checklist")
    assert payload["source"] == "live"


def test_assemble_payload_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        runner.assemble_payload(Path("/nonexistent/workdir"), preset_id="x", label="x")


def test_build_env_prepends_foundry_and_sets_workroot(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    env = runner.build_env(tmp_path)
    assert env["PATH"].startswith(str(runner.FOUNDRY_BIN))
    assert env["EADF_WORK_ROOT"] == str(tmp_path)


def test_stream_analysis_emits_stage_then_result(tmp_path, monkeypatch):
    class FakeProc:
        returncode = 0

        def __init__(self):
            self.stdout = iter([
                "Stage 1 complete: x\n",
                "Stage 2 complete: x\n",
                "Stage 3 complete: x\n",
                "Stage 4 complete: x\n",
                "Stage 5 complete: x\n",
            ])

        def wait(self):
            return 0

    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: FakeProc())
    # workdir that stream_analysis will read: point _run_dir at the fixture dir
    monkeypatch.setattr(runner, "_run_dir", lambda work_root, run_id: FIX)

    import presets
    preset = presets.get("storage_collision")
    events = list(runner.stream_analysis(preset, tmp_path))
    stages = [e for e in events if e["type"] == "stage"]
    results = [e for e in events if e["type"] == "result"]
    logs = [e for e in events if e["type"] == "log"]
    assert [e["stage"] for e in stages] == [1, 2, 3, 4, 5]
    assert len(results) == 1
    assert results[0]["payload"]["behavior"] == "Introduce Vulnerability"
    # the exact command is surfaced as the first log line
    assert logs[0]["line"].startswith("$ ") and "eadf" in logs[0]["line"]


@pytest.mark.slow
def test_real_sc01_end_to_end(tmp_path):
    import presets
    p = presets.get("storage_collision")
    payload = runner.run_analysis(p, tmp_path)
    assert payload["behavior"] == "Introduce Vulnerability"
    assert payload["risk_level"] == "Critical"
    assert any(c["slot"] == 0 for c in payload["storage"]["collisions"])

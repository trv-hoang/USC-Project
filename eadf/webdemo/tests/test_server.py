import json

import server


def client():
    server.app.config.update(TESTING=True)
    return server.app.test_client()


def test_presets_endpoint_lists_four():
    resp = client().get("/api/presets")
    assert resp.status_code == 200
    data = resp.get_json()
    assert [p["id"] for p in data] == ["storage_collision", "uninitialized", "unauthorized", "smooth"]
    assert data[0]["expected_behavior"] == "Introduce Vulnerability"


def test_source_endpoint_returns_solidity():
    resp = client().get("/api/source?preset=storage_collision&version=v2")
    assert resp.status_code == 200
    assert "collisionVar" in resp.get_json()["code"]


def test_source_endpoint_unknown_preset_404():
    assert client().get("/api/source?preset=nope&version=v1").status_code == 404


def test_algorithm_endpoint_returns_real_source():
    data = client().get("/api/algorithm").get_json()
    assert len(data) == 3
    names = [a["name"] for a in data]
    assert "CompareSlotMappings" in names
    for a in data:
        assert a["code"].lstrip().startswith("def ")
        assert a["file"].startswith("eadf/")
        assert a["pseudo"].strip()  # pseudocode from thesis present
        assert a["module"].startswith("Module ")


def test_dataset_endpoint_returns_benchmark_and_metrics():
    d = client().get("/api/dataset").get_json()
    assert d["total"] == 18
    # behavior distribution sums to 18
    assert sum(b["count"] for b in d["behavior"]) == 18
    # vuln-type distribution matches SPEC §6.5.2 B.4 (set-union per pair, total 17)
    assert sum(v["count"] for v in d["vulns"]) == 17
    assert {p["label"] for p in d["proxy"]} == {"UUPS", "Transparent"}
    assert d["metrics"]["eadf"]["f1"] == 1.0
    assert round(d["metrics"]["baseline"]["f1"], 4) == 0.3478


def test_analyze_streams_stage_and_result_events(monkeypatch):
    def fake_stream(preset, work_root):
        yield {"type": "stage", "stage": 1}
        yield {"type": "stage", "stage": 2}
        yield {"type": "result", "payload": {"behavior": "Introduce Vulnerability"}}

    monkeypatch.setattr(server.runner, "stream_analysis", fake_stream)
    resp = client().get("/api/analyze?preset=storage_collision")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "event: stage" in body
    assert "event: result" in body
    assert "Introduce Vulnerability" in body


def test_analyze_falls_back_to_cache_on_error(monkeypatch, tmp_path):
    def boom(preset, work_root):
        raise RuntimeError("slither exploded")
        yield  # make it a generator

    monkeypatch.setattr(server.runner, "stream_analysis", boom)
    cache_payload = {"behavior": "Introduce Vulnerability", "source": "cached"}
    (tmp_path / "storage_collision.json").write_text(json.dumps(cache_payload))
    monkeypatch.setattr(server, "CACHE_DIR", tmp_path)

    resp = client().get("/api/analyze?preset=storage_collision")
    body = resp.get_data(as_text=True)
    assert "event: result" in body
    assert '"source": "cached"' in body or '"source":"cached"' in body

"""Flask server for the EADF web demo."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from flask import Flask, Response, jsonify, request, send_from_directory  # noqa: E402

import algorithms  # noqa: E402
import dataset as dataset_mod  # noqa: E402
import presets  # noqa: E402
import runner  # noqa: E402

HERE = Path(__file__).resolve().parent
STATIC_DIR = HERE / "static"
CACHE_DIR = HERE / "cache"

app = Flask(__name__, static_folder=None)
# Never cache assets — avoids a stale browser-cached app.js/css during the demo.
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def _no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, must-revalidate"
    return resp


@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.get("/static/<path:filename>")
def static_files(filename: str):
    return send_from_directory(STATIC_DIR, filename)


@app.get("/api/presets")
def api_presets():
    return jsonify([
        {
            "id": p.id, "label": p.label, "scenario": p.scenario,
            "description": p.description, "expected_behavior": p.expected_behavior,
        }
        for p in presets.PRESETS
    ])


@app.get("/api/algorithm")
def api_algorithm():
    return jsonify(algorithms.algorithms())


@app.get("/api/dataset")
def api_dataset():
    return jsonify(dataset_mod.dataset())


@app.get("/api/source")
def api_source():
    p = presets.get(request.args.get("preset", ""))
    version = request.args.get("version", "v1")
    if p is None or version not in ("v1", "v2"):
        return jsonify({"error": "unknown preset/version"}), 404
    path = p.v1 if version == "v1" else p.v2
    return jsonify({"code": path.read_text()})


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _analyze_events(preset):
    """Generator of SSE strings: stage events, then result. Falls back to cache on error."""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for ev in runner.stream_analysis(preset, Path(tmp)):
                if ev["type"] == "log":
                    yield _sse("log", {"line": ev["line"]})
                elif ev["type"] == "stage":
                    yield _sse("stage", {"stage": ev["stage"]})
                elif ev["type"] == "result":
                    yield _sse("result", ev["payload"])
    except Exception as e:  # noqa: BLE001 - demo safety net
        cache_file = CACHE_DIR / f"{preset.id}.json"
        if cache_file.exists():
            payload = json.loads(cache_file.read_text())
            payload["source"] = "cached"
            yield _sse("fallback", {"message": str(e)})
            yield _sse("log", {"line": f"[!] live run failed: {e}"})
            yield _sse("log", {"line": f"[=] loading cached result: cache/{preset.id}.json"})
            for n in (1, 2, 3, 4, 5):
                yield _sse("stage", {"stage": n})
            yield _sse("result", payload)
        else:
            yield _sse("error", {"message": str(e)})


@app.get("/api/analyze")
def api_analyze():
    p = presets.get(request.args.get("preset", ""))
    if p is None:
        return jsonify({"error": "unknown preset"}), 404
    return Response(_analyze_events(p), mimetype="text/event-stream")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7000)
    args = ap.parse_args()
    app.run(host="127.0.0.1", port=args.port, threaded=True)


if __name__ == "__main__":
    main()

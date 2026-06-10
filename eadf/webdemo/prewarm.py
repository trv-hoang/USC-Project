"""Pre-warm solc cache and write a fallback payload per preset to cache/<id>.json.

Run from repo root with foundry on PATH:
    PATH="$HOME/.foundry/bin:$PATH" eadf/.venv/bin/python eadf/webdemo/prewarm.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import presets  # noqa: E402
import runner  # noqa: E402

CACHE_DIR = Path(__file__).resolve().parent / "cache"


def main() -> int:
    CACHE_DIR.mkdir(exist_ok=True)
    if not runner.FOUNDRY_BIN.joinpath("forge").exists():
        print(f"[!] forge not found at {runner.FOUNDRY_BIN} — install Foundry first.")
        return 1
    ok = 0
    for p in presets.PRESETS:
        print(f"[*] Pre-warming {p.id} ({p.pair_id}) ...", flush=True)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                payload = runner.run_analysis(p, Path(tmp))
            payload["source"] = "cached"
            (CACHE_DIR / f"{p.id}.json").write_text(json.dumps(payload, indent=2))
            print(f"    -> ok: behavior={payload['behavior']} risk={payload['risk_level']}")
            ok += 1
        except Exception as e:  # noqa: BLE001 - demo tooling, report and continue
            print(f"    [!] failed: {e}")
    print(f"[=] pre-warmed {ok}/{len(presets.PRESETS)} presets into {CACHE_DIR}")
    return 0 if ok == len(presets.PRESETS) else 1


if __name__ == "__main__":
    raise SystemExit(main())

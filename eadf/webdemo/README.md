# EADF Web Demo

Live visualizer for the EADF security detection, for the thesis defense.

## Run (one command)

```bash
cd <repo-root>
eadf/webdemo/run.sh
```

This prepends Foundry to PATH, pre-warms solc + builds the fallback cache for all
4 presets, starts the Flask server, and opens the browser at http://localhost:7000.

Skip the (slow) pre-warm on subsequent runs:

```bash
eadf/webdemo/run.sh --skip-prewarm
```

## Demo flow (in the browser)

1. Pick a scenario from the dropdown (Storage Collision / Uninitialized / Unauthorized / Smooth).
2. Click **Analyze** → the M1–M5 pipeline lights up as the real EADF run progresses.
3. Read the result: upgrade-behavior + risk badges, Storage Slot Differential
   (collision in red), findings, matched-pair confidence, security checklist.

The **Smooth** preset shows EADF staying quiet (no false alarm) — the precision story.

## Safety net

If a live run fails (bad projector environment, etc.), the UI automatically falls
back to the pre-warmed `cache/<preset>.json` and tags the result "chế độ dự phòng".
The demo never crashes.

## Requirements

- `eadf/.venv` (python3.13) with `pip install -e "eadf/.[demo]"`
- Foundry (`forge`) installed at `~/.foundry/bin`

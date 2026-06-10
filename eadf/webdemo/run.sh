#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV="$REPO_ROOT/eadf/.venv"
PORT="${PORT:-7000}"

export PATH="$HOME/.foundry/bin:$PATH"

if [ ! -x "$VENV/bin/eadf" ]; then
  echo "[!] EADF venv missing/broken at $VENV"
  echo "    Rebuild:  python3.13 -m venv eadf/.venv && eadf/.venv/bin/pip install -e 'eadf/.[demo]'"
  exit 1
fi
if ! command -v forge >/dev/null 2>&1; then
  echo "[!] forge not found. Install Foundry: https://book.getfoundry.sh"
  exit 1
fi

cd "$REPO_ROOT"
if [ "${1:-}" != "--skip-prewarm" ]; then
  echo "[*] Pre-warming (solc + fallback cache)..."
  "$VENV/bin/python" eadf/webdemo/prewarm.py || echo "[!] prewarm had issues; live + any existing cache still usable"
fi

echo "[*] Starting EADF demo at http://localhost:$PORT"
"$VENV/bin/python" eadf/webdemo/server.py --port "$PORT" &
SERVER_PID=$!
sleep 1
( command -v open >/dev/null && open "http://localhost:$PORT" ) || true
trap 'kill $SERVER_PID 2>/dev/null || true' INT TERM
wait $SERVER_PID

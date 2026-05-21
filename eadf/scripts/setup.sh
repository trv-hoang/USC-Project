#!/usr/bin/env bash
set -euo pipefail

echo "== Installing Solc 0.8.24 via solc-select =="
solc-select install 0.8.24
solc-select use 0.8.24
solc --version

echo "== Smoke-testing slither =="
slither --version

echo "== Setup complete =="

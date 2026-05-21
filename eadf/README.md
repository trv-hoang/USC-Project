# EADF — Evolution-Aware Detection Framework

> **Status: Under construction.** Core analysis modules land in Phases 3–8 of the MVP plan.

EADF is a Python tool for detecting security regressions across upgrade boundaries in proxy-based
upgradeable smart contracts (UUPS, Transparent Proxy, Beacon). It statically analyses two contract
versions — using Slither — and scores each finding by whether the logic actually changed between
upgrades, cutting false positives that arise from upgrade-unaware scanners.

For the full system design see
[`docs/superpowers/specs/2026-05-21-eadf-mvp-design.md`](../docs/superpowers/specs/2026-05-21-eadf-mvp-design.md)
and the top-level thesis specification at [`SPEC.md`](../SPEC.md).

---

## Install

Requires Python 3.10+.

```bash
cd eadf
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Copy `.env.example` to `.env` and fill in your Etherscan API key if you plan to
fetch contracts from the network:

```bash
cp .env.example .env
# edit .env and set ETHERSCAN_API_KEY=<your key>
```

---

## Quickstart

> **Note:** The CLI is not functional yet — `eadf.cli` is created in Task 10 (Phase 8).
> The commands below show the intended interface once the full MVP is in place.

```bash
# Analyse two local Solidity files
eadf run --local-v1 path/to/ImplementationV1.sol \
         --local-v2 path/to/ImplementationV2.sol

# Fetch both versions from Etherscan by proxy address + block numbers
eadf run --proxy 0xYourProxyAddress \
         --block-v1 18000000 \
         --block-v2 19000000
```

The tool will print a ranked list of findings with per-finding upgrade-relevance scores and
exit with a non-zero code if any high-severity, upgrade-relevant issues are found.

---

## Development

```bash
pytest            # run the test suite
ruff check eadf   # lint
mypy eadf         # type-check
```

"""Etherscan source provider — fetches proxy upgrade history + impl source code.

Reads `Upgraded(address indexed implementation)` event logs to discover the
upgrade chain, takes the last two implementations as (V1, V2), and downloads
their verified source via the `getsourcecode` API endpoint. The base API URL
is the v1 endpoint (https://api.etherscan.io/api). For the v2/multichain
endpoint (https://api.etherscan.io/v2/api), pass it via `api_base`.

Rate limits: Etherscan free tier permits 5 req/s. We make at most 3 requests
per fetch (1 getLogs + 2 getsourcecode), well within the limit.
"""
from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

from ..config import SOLC_VERSION
from ..models import SourceBundle, SourceMetadata


# keccak256("Upgraded(address)") — the ERC-1967 Upgraded event signature
_UPGRADED_TOPIC = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"

# Default v1 endpoint
_DEFAULT_API_BASE = "https://api.etherscan.io/api"


class EtherscanSource:
    def __init__(self, proxy_address: str, api_key: str, api_base: str = _DEFAULT_API_BASE):
        self.proxy_address = proxy_address
        self.api_key = api_key
        self.api_base = api_base

    def fetch(self, workdir: Path) -> SourceBundle:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)

        # 1. Pull all Upgraded event logs for this proxy
        upgrades = self._get_upgrade_history()
        if len(upgrades) < 2:
            raise RuntimeError(
                f"Proxy {self.proxy_address} has fewer than 2 upgrade history "
                f"entries (found {len(upgrades)}). Cannot extract V1, V2 pair."
            )

        # 2. Take the last two implementations
        v1_impl, v1_block = upgrades[-2]
        v2_impl, v2_block = upgrades[-1]

        # 3. Fetch and write source for each
        v1_dir = workdir / "v1"
        v2_dir = workdir / "v2"
        v1_dir.mkdir(parents=True, exist_ok=True)
        v2_dir.mkdir(parents=True, exist_ok=True)
        v1_label = self._fetch_source(v1_impl, v1_dir)
        v2_label = self._fetch_source(v2_impl, v2_dir)

        # 4. Write metadata
        metadata = SourceMetadata(
            source_type="etherscan",
            v1={"path_or_address": v1_impl, "label": v1_label, "compiler": SOLC_VERSION},
            v2={"path_or_address": v2_impl, "label": v2_label, "compiler": SOLC_VERSION},
            fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            proxy_address=self.proxy_address,
            upgrade_block=v2_block,
        )
        (workdir / "metadata.json").write_text(json.dumps(asdict(metadata), indent=2))

        return SourceBundle(v1_dir=v1_dir, v2_dir=v2_dir, metadata=metadata)

    # --- private helpers ---

    def _get_upgrade_history(self) -> list[tuple[str, int]]:
        """Return list of (impl_address, block_number) in event-log order."""
        params = {
            "module": "logs",
            "action": "getLogs",
            "address": self.proxy_address,
            "topic0": _UPGRADED_TOPIC,
            "fromBlock": 0,
            "toBlock": "latest",
            "apikey": self.api_key,
        }
        resp = requests.get(self.api_base, params=params, timeout=30)
        payload = resp.json()
        if payload.get("status") != "1" or not isinstance(payload.get("result"), list):
            return []
        out: list[tuple[str, int]] = []
        for entry in payload["result"]:
            topics = entry.get("topics", [])
            if len(topics) < 2:
                continue
            # topic[1] = padded address of new implementation
            padded = topics[1]
            addr = "0x" + padded[-40:]
            block = int(entry.get("blockNumber", "0x0"), 16)
            out.append((addr, block))
        return out

    def _fetch_source(self, impl_address: str, dest_dir: Path) -> str:
        """Download verified source for `impl_address` into `dest_dir`.
        Returns the contract label (name) for use in metadata.
        """
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": impl_address,
            "apikey": self.api_key,
        }
        resp = requests.get(self.api_base, params=params, timeout=30)
        payload = resp.json()
        if payload.get("status") != "1":
            raise RuntimeError(
                f"Etherscan getsourcecode failed for {impl_address}: "
                f"{payload.get('result', payload)}"
            )
        result = payload.get("result")
        if not isinstance(result, list) or not result:
            raise RuntimeError(f"Empty getsourcecode result for {impl_address}")
        entry = result[0]
        source_code = entry.get("SourceCode", "")
        contract_name = entry.get("ContractName") or f"Unknown_{impl_address[-6:]}"

        if not source_code:
            raise RuntimeError(
                f"Contract {impl_address} is not verified (no source code). "
                f"Skip this proxy or pick a verified one."
            )

        # Etherscan returns either raw source OR a JSON-encoded "Standard JSON Input"
        # blob wrapped in `{{...}}` (note double braces). For MVP we handle both:
        # if it starts with `{{`, peel and parse; otherwise treat as raw single-file.
        if source_code.startswith("{{") and source_code.endswith("}}"):
            try:
                inner = json.loads(source_code[1:-1])
                sources = inner.get("sources", {})
                for filename, src_meta in sources.items():
                    file_path = dest_dir / Path(filename).name
                    file_path.write_text(src_meta.get("content", ""))
            except (json.JSONDecodeError, AttributeError):
                # Fall back to raw write
                (dest_dir / f"{contract_name}.sol").write_text(source_code)
        else:
            (dest_dir / f"{contract_name}.sol").write_text(source_code)

        return contract_name

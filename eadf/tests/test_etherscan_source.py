"""Tests for EtherscanSource using fake HTTP (monkeypatched requests.get).

The mainnet smoke test against a real proxy is documented but not exercised
in CI — it requires an ETHERSCAN_API_KEY env var and a network round-trip.
"""
import json
from pathlib import Path
import pytest
import requests

from eadf.module1_collector.etherscan_source import EtherscanSource


def test_fetches_two_implementations(tmp_path, monkeypatch):
    def fake_get(url, params=None, **kw):
        class R:
            status_code = 200
            def json(self_inner):
                if params and params.get("action") == "getLogs":
                    return {"status": "1", "result": [
                        {"topics": ["0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
                                    "0x0000000000000000000000001111111111111111111111111111111111111111"],
                         "blockNumber": "0x10"},
                        {"topics": ["0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
                                    "0x0000000000000000000000002222222222222222222222222222222222222222"],
                         "blockNumber": "0x20"},
                    ]}
                if params and params.get("action") == "getsourcecode":
                    addr = params.get("address", "")
                    return {"status": "1", "result": [{
                        "SourceCode": f"// SPDX-License-Identifier: MIT\ncontract C_{addr[-4:]}{{}}\n",
                        "ContractName": f"C_{addr[-4:]}",
                        "CompilerVersion": "v0.8.24+commit.e11b9ed9",
                    }]}
                return {"status": "0", "result": []}
        return R()

    monkeypatch.setattr(requests, "get", fake_get)

    src = EtherscanSource(proxy_address="0xabc", api_key="K")
    bundle = src.fetch(tmp_path)

    assert list((tmp_path / "v1").iterdir()), "v1 must contain a file"
    assert list((tmp_path / "v2").iterdir()), "v2 must contain a file"
    meta = json.loads((tmp_path / "metadata.json").read_text())
    assert meta["source_type"] == "etherscan"
    assert meta["upgrade_block"] == 32  # last block (0x20)


def test_unverified_skips_gracefully(tmp_path, monkeypatch):
    def fake_get(url, params=None, **kw):
        class R:
            status_code = 200
            def json(self_inner):
                if params and params.get("action") == "getLogs":
                    return {"status": "1", "result": []}
                return {"status": "0", "result": "Not verified"}
        return R()
    monkeypatch.setattr(requests, "get", fake_get)

    src = EtherscanSource(proxy_address="0xabc", api_key="K")
    with pytest.raises(RuntimeError, match="upgrade history"):
        src.fetch(tmp_path)

from pathlib import Path
import json
from eadf.module1_collector.local_source import LocalSource


def test_copies_v1_v2_and_writes_metadata(tmp_path):
    # Arrange — create dummy Solidity files
    v1 = tmp_path / "input_v1" / "LogicV1.sol"
    v1.parent.mkdir()
    v1.write_text("// SPDX-License-Identifier: MIT\ncontract LogicV1 {}\n")
    v2 = tmp_path / "input_v2" / "LogicV2.sol"
    v2.parent.mkdir()
    v2.write_text("// SPDX-License-Identifier: MIT\ncontract LogicV2 {}\n")

    workdir = tmp_path / "work"
    workdir.mkdir()

    src = LocalSource(v1_path=v1, v2_path=v2)
    bundle = src.fetch(workdir)

    # Assert — files copied, metadata.json written
    assert (workdir / "v1" / "LogicV1.sol").exists()
    assert (workdir / "v2" / "LogicV2.sol").exists()
    meta = json.loads((workdir / "metadata.json").read_text())
    assert meta["source_type"] == "local"
    assert meta["v1"]["label"] == "LogicV1"
    assert meta["v2"]["label"] == "LogicV2"
    assert meta["proxy_address"] == "LOCAL_TEST"


def test_raises_if_source_missing(tmp_path):
    import pytest
    src = LocalSource(v1_path=tmp_path / "nope.sol", v2_path=tmp_path / "also_nope.sol")
    with pytest.raises(FileNotFoundError):
        src.fetch(tmp_path / "work")

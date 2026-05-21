"""Local file source provider — used for dev/test and pre-deployment audit."""
from __future__ import annotations
import json
import shutil
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from ..config import SOLC_VERSION
from ..models import SourceBundle, SourceMetadata


class LocalSource:
    def __init__(self, v1_path: Path, v2_path: Path):
        self.v1_path = Path(v1_path)
        self.v2_path = Path(v2_path)

    def fetch(self, workdir: Path) -> SourceBundle:
        workdir = Path(workdir)
        if not self.v1_path.exists():
            raise FileNotFoundError(self.v1_path)
        if not self.v2_path.exists():
            raise FileNotFoundError(self.v2_path)

        v1_dir = workdir / "v1"
        v2_dir = workdir / "v2"
        v1_dir.mkdir(parents=True, exist_ok=True)
        v2_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.v1_path, v1_dir / self.v1_path.name)
        shutil.copy2(self.v2_path, v2_dir / self.v2_path.name)

        metadata = SourceMetadata(
            source_type="local",
            v1={"path_or_address": str(self.v1_path), "label": self.v1_path.stem, "compiler": SOLC_VERSION},
            v2={"path_or_address": str(self.v2_path), "label": self.v2_path.stem, "compiler": SOLC_VERSION},
            fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            proxy_address="LOCAL_TEST",
            upgrade_block=None,
        )
        (workdir / "metadata.json").write_text(json.dumps(asdict(metadata), indent=2))

        return SourceBundle(v1_dir=v1_dir, v2_dir=v2_dir, metadata=metadata)

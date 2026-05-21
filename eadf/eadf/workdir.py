"""Per-run work directory management. Stage outputs live here."""
from __future__ import annotations
import json
import os
import tempfile
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Optional

class WorkDir:
    def __init__(self, root: Path, run_id: Optional[str] = None):
        self.root = Path(root)
        self.run_id = run_id or f"run_{int(time.time())}"

    @property
    def base(self) -> Path:
        return self.root / self.run_id

    def ensure(self) -> None:
        self.base.mkdir(parents=True, exist_ok=True)

    def stage_dir(self, n: int) -> Path:
        names = {1: "stage1_sources"}
        return self.base / names.get(n, f"stage{n}")

    def stage_path(self, n: int, filename: str) -> Path:
        return self.base / f"stage{n}_{filename}"

    def write_json(self, path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = _to_jsonable(data)
        # Atomic write: tmp file → rename
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_", suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2, default=str)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def read_json(self, path: Path) -> Any:
        return json.loads(path.read_text())


def _to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return _to_jsonable(asdict(obj))
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    return obj

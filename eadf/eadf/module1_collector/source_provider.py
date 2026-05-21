from pathlib import Path
from typing import Protocol
from ..models import SourceBundle


class SourceProvider(Protocol):
    """Returns a SourceBundle with v1/v2 source directories populated."""
    def fetch(self, workdir: Path) -> SourceBundle: ...

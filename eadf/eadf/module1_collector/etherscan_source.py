"""Etherscan source provider — full implementation lands in Phase 9."""
from pathlib import Path
from ..models import SourceBundle


class EtherscanSource:
    def __init__(self, proxy_address: str, api_key: str):
        self.proxy_address = proxy_address
        self.api_key = api_key

    def fetch(self, workdir: Path) -> SourceBundle:
        raise NotImplementedError("EtherscanSource wired in Phase 9")

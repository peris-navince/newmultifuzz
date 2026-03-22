from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class RegisterMatch:
    peripheral: str
    register: str
    absolute_address: int
    absolute_address_hex: str
    size_bytes: int
    field_names: List[str]


class ManualMMIOIndex:
    def __init__(self, data: Dict[str, Any]):
        self.data = data or {}
        self.by_addr: Dict[int, RegisterMatch] = {}
        self._build()

    @classmethod
    def from_path(cls, path: Optional[str]) -> Optional["ManualMMIOIndex"]:
        if not path:
            return None
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"manual mmio map not found: {p}")
        return cls(json.loads(p.read_text(encoding="utf-8")))

    def _build(self) -> None:
        periph = str(self.data.get("peripheral") or "").strip()
        for reg in self.data.get("registers") or []:
            try:
                addr = int(reg.get("absoluteAddress"))
            except Exception:
                continue
            match = RegisterMatch(
                peripheral=periph,
                register=str(reg.get("name") or "").strip(),
                absolute_address=addr,
                absolute_address_hex=str(reg.get("absoluteAddress_hex") or hex(addr)),
                size_bytes=int(reg.get("size_bytes") or max(1, int(reg.get("size_bits") or 32) // 8)),
                field_names=[
                    str(f.get("name") or "").strip()
                    for f in (reg.get("fields") or [])
                    if str(f.get("name") or "").strip()
                ],
            )
            self.by_addr[addr] = match

    def resolve(self, address: int) -> Optional[RegisterMatch]:
        if address in self.by_addr:
            return self.by_addr[address]
        for base, match in self.by_addr.items():
            if base <= address < base + max(1, match.size_bytes):
                return match
        return None

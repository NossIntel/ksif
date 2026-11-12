"""MAC vendor lookup from the OUI databases shipped with nmap / arp-scan."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

OUI_PATHS = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/arp-scan/ieee-oui.txt",
    "/usr/share/ieee-data/oui.txt",
)
_ENTRY = re.compile(r"^([0-9A-Fa-f]{6})\s+(.+)$")
_IEEE_ENTRY = re.compile(r"^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+)$")


class OuiDatabase:
    """Maps the first three bytes of a MAC address to its manufacturer."""

    def __init__(self, paths: Sequence[str | Path] = OUI_PATHS) -> None:
        self._vendors: dict[str, str] = {}
        self.source: Path | None = None
        for candidate in paths:
            path = Path(candidate)
            if path.is_file():
                self._load(path)
                if self._vendors:
                    self.source = path
                    break

    def _load(self, path: Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = _IEEE_ENTRY.match(line) or _ENTRY.match(line)
            if match:
                self._vendors.setdefault(match.group(1).upper(), match.group(2).strip())

    def lookup(self, mac: str | None) -> str | None:
        """Return the vendor for *mac* or None when unknown."""
        if not mac:
            return None
        digits = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(digits) < 6:
            return None
        return self._vendors.get(digits[:6])

    def __len__(self) -> int:
        return len(self._vendors)

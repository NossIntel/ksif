"""Catalogue of every tool integration (used by Configuration and --check)."""

from __future__ import annotations

from core.subprocess_manager import SubprocessManager
from integrations.arp_scan import ArpScanIntegration
from integrations.base import ToolIntegration
from integrations.john import JohnIntegration
from integrations.masscan import MasscanIntegration
from integrations.nmap import NmapIntegration
from integrations.osint_tools import (
    AmassIntegration,
    DigIntegration,
    SubfinderIntegration,
    TheHarvesterIntegration,
    WhoisIntegration,
)
from integrations.tshark import TsharkIntegration
from integrations.web_tools import (
    NiktoIntegration,
    NucleiIntegration,
    WhatWebIntegration,
    WpscanIntegration,
)
from integrations.wifi_tools import IwIntegration, NmcliIntegration

# (module label, integration class)
CATALOGUE: list[tuple[str, type[ToolIntegration]]] = [
    ("Network Discovery", NmapIntegration),
    ("Network Discovery", ArpScanIntegration),
    ("Network Discovery", MasscanIntegration),
    ("Network Discovery", TsharkIntegration),
    ("OSINT", WhoisIntegration),
    ("OSINT", DigIntegration),
    ("OSINT", SubfinderIntegration),
    ("OSINT", AmassIntegration),
    ("OSINT", TheHarvesterIntegration),
    ("Web Security", WhatWebIntegration),
    ("Web Security", NiktoIntegration),
    ("Web Security", NucleiIntegration),
    ("Web Security", WpscanIntegration),
    ("Wi-Fi Audit", NmcliIntegration),
    ("Wi-Fi Audit", IwIntegration),
    ("Password Lab", JohnIntegration),
]


def all_integrations(runner: SubprocessManager) -> list[tuple[str, ToolIntegration]]:
    """Instantiate every known integration."""
    return [(label, cls(runner)) for label, cls in CATALOGUE]


async def self_test_all(runner: SubprocessManager) -> list[dict[str, str | bool]]:
    """Really run each tool's probe; one row per tool."""
    rows: list[dict[str, str | bool]] = []
    for label, tool in all_integrations(runner):
        ok, detail = await tool.self_test()
        rows.append({"module": label, "tool": tool.binary, "ok": ok, "detail": detail})
    return rows

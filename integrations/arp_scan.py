"""arp-scan integration (layer-2 discovery on a local segment)."""

from __future__ import annotations

import ipaddress
import re

from core.models import Host, Target, TargetKind
from core.validator import ValidationError, validate_interface
from integrations.base import ToolIntegration

_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s*(.*)$")


class ArpScanIntegration(ToolIntegration):
    """Wrapper around ``arp-scan`` (IPv4 only, needs root)."""

    binary = "arp-scan"
    install_hint = "sudo apt install arp-scan"
    version_pattern = r"arp-scan (\d+\.\d+(?:\.\d+)*)"

    def scan_args(self, interface: str, target: Target) -> list[str]:
        """ARP sweep of an IPv4 address or network on *interface*."""
        if target.kind not in (TargetKind.IPV4, TargetKind.CIDR) or ":" in target.value:
            raise ValidationError("arp-scan only supports IPv4 addresses and networks")
        return [f"--interface={validate_interface(interface)}", "--retry=2", target.value]

    def parse(self, output: str) -> list[Host]:
        """Parse ``IP<tab>MAC<tab>Vendor`` lines, ignoring banners and duplicates."""
        hosts: dict[str, Host] = {}
        for line in output.splitlines():
            match = _LINE.match(line.strip())
            if not match:
                continue
            address, mac, vendor = match.groups()
            try:
                ipaddress.IPv4Address(address)
            except ValueError:
                continue
            vendor = re.sub(r"\s*\(DUP: \d+\)\s*$", "", vendor).strip()
            if vendor.startswith("(Unknown"):
                vendor = ""
            hosts.setdefault(
                address, Host(address=address, family="ipv4", mac=mac.lower(), vendor=vendor or None)
            )
        return list(hosts.values())

"""Masscan integration with a hard rate ceiling."""

from __future__ import annotations

import ipaddress
import json

from core.models import Host, Port, Target, TargetKind
from core.validator import ValidationError, validate_port_spec
from integrations.base import ParseError, ToolIntegration

MAX_RATE = 1000  # packets/second hard ceiling


class MasscanIntegration(ToolIntegration):
    """Wrapper around ``masscan`` (IPv4 only, needs root)."""

    binary = "masscan"
    install_hint = "sudo apt install masscan"
    version_pattern = r"[Mm]asscan version (\d+\.\d+(?:\.\d+)*)"

    def scan_args(self, target: Target, ports: str, rate: int = 100) -> list[str]:
        """Fast TCP sweep; *rate* is capped at MAX_RATE."""
        if target.kind not in (TargetKind.IPV4, TargetKind.CIDR) or ":" in target.value:
            raise ValidationError("masscan support is limited to IPv4 addresses and networks")
        capped = max(1, min(int(rate), MAX_RATE))
        return ["-p", validate_port_spec(ports), "--rate", str(capped), "-oJ", "-", target.value]

    def parse(self, output: str) -> list[Host]:
        """Parse ``-oJ`` output (tolerates the trailing-comma quirks of old versions)."""
        text = output.strip()
        if not text:
            return []
        records: list[dict] = []
        try:
            data = json.loads(text)
            records = [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
            if not isinstance(data, list):
                raise ParseError("masscan JSON is not a list")
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if not line.startswith("{") or line.replace(" ", "").startswith("{finished"):
                    continue  # brackets, or the non-JSON "{finished: 1}" trailer of old versions
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ParseError(f"masscan output is malformed: {exc}") from exc
            if not records and text not in ("[", "[]", "[\n]"):
                raise ParseError("masscan output is not JSON")
        hosts: dict[str, Host] = {}
        for record in records:
            address = record.get("ip")
            if not isinstance(address, str):
                continue
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            host = hosts.setdefault(address, Host(address=address, family="ipv4"))
            for port in record.get("ports") or []:
                if port.get("status") != "open":
                    continue
                number, proto = port.get("port"), port.get("proto", "tcp")
                if isinstance(number, int) and not any(
                    p.number == number and p.protocol == proto for p in host.ports
                ):
                    host.ports.append(Port(number, proto, "open"))
        return list(hosts.values())

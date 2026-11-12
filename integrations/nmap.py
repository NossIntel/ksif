"""Nmap integration: typed command builders and XML parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from core.models import Host, Port, Target, TargetKind
from core.validator import ValidationError, validate_port_spec
from integrations.base import ParseError, ToolIntegration

MAX_RATE = 1000  # packets/second hard ceiling
MAX_TIMING = 4  # never -T5 (insane)
_KINDS = (TargetKind.IPV4, TargetKind.IPV6, TargetKind.CIDR, TargetKind.DOMAIN)


class NmapIntegration(ToolIntegration):
    """Wrapper around ``nmap``. Output is always requested as XML on stdout."""

    binary = "nmap"
    install_hint = "sudo apt install nmap"
    version_pattern = r"Nmap version (\d+\.\d+(?:\.\d+)*)"

    @staticmethod
    def _base(target: Target) -> list[str]:
        if target.kind not in _KINDS:
            raise ValidationError(f"nmap does not accept {target.kind.value} targets")
        args = ["-oX", "-"]
        if target.kind is TargetKind.IPV6 or (target.kind is TargetKind.CIDR and ":" in target.value):
            args.append("-6")
        return args

    def host_discovery_args(self, target: Target) -> list[str]:
        """Ping sweep (no port scan)."""
        return ["-sn", *self._base(target), target.value]

    def port_scan_args(
        self,
        target: Target,
        *,
        ports: str | None = None,
        top_ports: int | None = 1000,
        service_detection: bool = False,
        os_detection: bool = False,
        traceroute: bool = False,
        timing: int = 3,
        max_rate: int = 300,
    ) -> list[str]:
        """Port scan with optional service/OS detection. Rate and timing are capped."""
        args = self._base(target)
        args.append(f"-T{max(0, min(int(timing), MAX_TIMING))}")
        args += ["--max-rate", str(max(1, min(int(max_rate), MAX_RATE)))]
        if ports:
            args += ["-p", validate_port_spec(ports)]
        elif top_ports:
            args += ["--top-ports", str(max(1, min(int(top_ports), 65535)))]
        if service_detection:
            args.append("-sV")
        if os_detection:
            args.append("-O")
        if traceroute:
            args.append("--traceroute")
        args.append(target.value)  # target is always the final argument
        return args

    def parse_xml(self, xml: str) -> list[Host]:
        """Parse ``nmap -oX`` output into hosts (only hosts that are up).

        Raises:
            ParseError: empty, malformed or truncated XML (e.g. a killed scan).
        """
        if not xml or not xml.strip():
            raise ParseError("nmap produced no output")
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            raise ParseError(f"nmap XML is incomplete or malformed: {exc}") from exc
        if root.tag != "nmaprun":
            raise ParseError("not an nmap XML document")
        if root.find("runstats") is None:
            raise ParseError("nmap XML has no runstats (scan did not finish)")
        return [host for host in map(self._parse_host, root.findall("host")) if host is not None]

    @staticmethod
    def _parse_host(node: ET.Element) -> Host | None:
        status = node.find("status")
        if status is None or status.get("state") != "up":
            return None
        address = family = mac = vendor = None
        for addr in node.findall("address"):
            kind = addr.get("addrtype")
            if kind in ("ipv4", "ipv6") and address is None:
                address, family = addr.get("addr"), kind
            elif kind == "mac":
                mac, vendor = addr.get("addr"), addr.get("vendor")
        if not address or not family:
            return None
        hostname_node = node.find("hostnames/hostname")
        host = Host(
            address=address, family=family, mac=mac, vendor=vendor,
            hostname=hostname_node.get("name") if hostname_node is not None else None,
        )
        for port in node.findall("ports/port"):
            state_node = port.find("state")
            state = state_node.get("state", "") if state_node is not None else ""
            if state not in ("open", "open|filtered"):
                continue
            service = port.find("service")
            try:
                number = int(port.get("portid", ""))
            except ValueError:
                continue
            host.ports.append(
                Port(
                    number=number, protocol=port.get("protocol", "tcp"), state=state,
                    service=service.get("name") if service is not None else None,
                    product=service.get("product") if service is not None else None,
                    version=service.get("version") if service is not None else None,
                )
            )
        best: tuple[int, str] | None = None
        for match in node.findall("os/osmatch"):
            try:
                accuracy = int(match.get("accuracy", "0"))
            except ValueError:
                accuracy = 0
            if best is None or accuracy > best[0]:
                best = (accuracy, match.get("name", ""))
        if best and best[1]:
            host.os_accuracy, host.os_guess = best
        host.hops = [hop.get("ipaddr", "") for hop in node.findall("trace/hop") if hop.get("ipaddr")]
        return host

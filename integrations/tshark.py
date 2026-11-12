"""tshark integration: time-boxed passive capture summarised per host.

tshark is the command-line engine of Wireshark; captures can be opened in the
Wireshark GUI afterwards."""

from __future__ import annotations

import ipaddress
from collections import Counter

from core.models import Host
from core.validator import validate_interface
from integrations.base import ToolIntegration

MAX_DURATION = 300  # seconds
FIELDS = ("eth.src", "ip.src", "ipv6.src", "_ws.col.Protocol")


class TsharkIntegration(ToolIntegration):
    """Wrapper around ``tshark`` for passive observation only."""

    binary = "tshark"
    install_hint = "sudo apt install tshark"
    probe_arg = "-v"
    version_pattern = r"TShark \(Wireshark\) (\d+\.\d+(?:\.\d+)*)"

    def capture_args(self, interface: str, duration: int) -> list[str]:
        """Capture on *interface* for at most MAX_DURATION seconds (headers only)."""
        capped = max(1, min(int(duration), MAX_DURATION))
        args = ["-i", validate_interface(interface), "-a", f"duration:{capped}", "-n", "-l",
                "-T", "fields", "-E", "separator=/t"]
        for name in FIELDS:
            args += ["-e", name]
        return args

    def parse(self, output: str) -> tuple[list[Host], dict[str, int]]:
        """Return observed source hosts and a packet count per protocol."""
        hosts: dict[str, Host] = {}
        protocols: Counter[str] = Counter()
        for line in output.splitlines():
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) < 4:
                continue
            mac, ip4, ip6, proto = (p.strip() for p in parts[:4])
            if proto:
                protocols[proto] += 1
            for raw, family in ((ip4, "ipv4"), (ip6, "ipv6")):
                address = raw.split(",")[0]
                if not address:
                    continue
                try:
                    ip = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if ip.is_unspecified or ip.is_multicast:
                    continue
                hosts.setdefault(
                    ip.compressed, Host(address=ip.compressed, family=family, mac=mac.lower() or None)
                )
        return list(hosts.values()), dict(protocols)

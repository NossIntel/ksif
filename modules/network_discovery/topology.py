"""Subnet grouping and hop-based topology."""

from __future__ import annotations

import ipaddress

from core.models import Host


def subnet_map(hosts: list[Host]) -> dict[str, list[str]]:
    """Group host addresses by /24 (IPv4) or /64 (IPv6)."""
    groups: dict[str, list[str]] = {}
    for host in hosts:
        try:
            ip = ipaddress.ip_address(host.address)
        except ValueError:
            continue
        prefix = 24 if ip.version == 4 else 64
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False).compressed
        groups.setdefault(network, []).append(ip.compressed)
    return {net: sorted(addrs, key=lambda a: int(ipaddress.ip_address(a))) for net, addrs in sorted(groups.items())}


def topology_edges(hosts: list[Host], origin: str = "scanner") -> list[tuple[str, str]]:
    """Unique links derived from traceroute hops: origin -> hop1 -> ... -> host."""
    edges: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for host in hosts:
        path = [origin, *host.hops]
        if not host.hops or path[-1] != host.address:
            path.append(host.address)
        for left, right in zip(path, path[1:]):
            if left != right and (left, right) not in seen:
                seen.add((left, right))
                edges.append((left, right))
    return edges

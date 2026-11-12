"""Network Discovery actions registered with the engine."""

from __future__ import annotations

from typing import Any

from core.engine import Action, ActionContext, ActionOutput, Engine
from core.models import Host, Intrusiveness, TargetKind
from core.validator import validate_int, validate_interface, validate_port_spec
from integrations.arp_scan import ArpScanIntegration
from integrations.base import ParseError
from integrations.masscan import MasscanIntegration
from integrations.nmap import NmapIntegration
from integrations.tshark import MAX_DURATION, TsharkIntegration
from modules.network_discovery.device_classifier import classify_device
from modules.network_discovery.oui import OuiDatabase
from modules.network_discovery.topology import subnet_map, topology_edges

MODULE = "network_discovery"
NET_KINDS = frozenset({TargetKind.IPV4, TargetKind.IPV6, TargetKind.CIDR, TargetKind.DOMAIN})
V4_KINDS = frozenset({TargetKind.IPV4, TargetKind.CIDR})

_oui: OuiDatabase | None = None


def _oui_db() -> OuiDatabase:
    global _oui  # noqa: PLW0603 - lazy singleton, the OUI file is large
    if _oui is None:
        _oui = OuiDatabase()
    return _oui


def enrich(hosts: list[Host], oui: OuiDatabase | None = None) -> list[Host]:
    """Fill in vendor (from the OUI database) and device type."""
    database = oui or _oui_db()
    for host in hosts:
        if not host.vendor:
            host.vendor = database.lookup(host.mac)
        host.device_type = classify_device(host)
    return hosts


def _output(hosts: list[Host], extra: dict[str, Any] | None = None) -> ActionOutput:
    hosts = enrich(hosts)
    ports = sum(len(h.ports) for h in hosts)
    data: dict[str, Any] = {"subnets": subnet_map(hosts)}
    data.update(extra or {})
    return ActionOutput(hosts=hosts, summary=f"{len(hosts)} host(s) up, {ports} open port(s)", data=data)


async def _run_nmap(ctx: ActionContext, args: list[str]) -> list[Host]:
    nmap = NmapIntegration(ctx.runner)
    result = await ctx.runner.run(
        "nmap", args, authorization=ctx.authorization,
        timeout=ctx.settings.default_timeout_seconds, on_line=_progress_only(ctx),
    )
    ctx.save_raw(result.stdout, "xml", result.command)
    try:
        return nmap.parse_xml(result.stdout)
    except ParseError as exc:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else ""
        raise ParseError(f"{exc}{' - ' + detail if detail else ''}") from exc


def _progress_only(ctx: ActionContext):
    """XML is noisy: forward only short, human-meaningful lines to the UI."""

    def forward(line: str) -> None:
        stripped = line.strip()
        if stripped.startswith("<host ") or stripped.startswith("<address "):
            ctx.on_line(stripped[:120])

    return forward


async def host_discovery(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Ping sweep: which hosts are alive."""
    nmap = NmapIntegration(ctx.runner)
    return _output(await _run_nmap(ctx, nmap.host_discovery_args(ctx.target)))


async def port_scan(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """TCP port scan (top 1000 ports or an explicit list)."""
    ports = validate_port_spec(params["ports"]) if params.get("ports") else None
    nmap = NmapIntegration(ctx.runner)
    return _output(await _run_nmap(ctx, nmap.port_scan_args(ctx.target, ports=ports)))


async def service_os(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Service/version detection plus OS fingerprinting."""
    ports = validate_port_spec(params["ports"]) if params.get("ports") else None
    nmap = NmapIntegration(ctx.runner)
    args = nmap.port_scan_args(ctx.target, ports=ports, service_detection=True, os_detection=True)
    return _output(await _run_nmap(ctx, args))


async def topology(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Traceroute-based topology (top 100 ports to find a responsive port)."""
    nmap = NmapIntegration(ctx.runner)
    hosts = await _run_nmap(ctx, nmap.port_scan_args(ctx.target, top_ports=100, traceroute=True))
    return _output(hosts, {"edges": topology_edges(hosts)})


async def arp_scan(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Layer-2 sweep; finds hosts that ignore ICMP."""
    interface = validate_interface(str(params.get("interface", "")))
    if interface not in ctx.scope.interfaces:
        raise PermissionError(f"interface {interface} is not in the authorized scope")
    tool = ArpScanIntegration(ctx.runner)
    result = await ctx.runner.run(
        "arp-scan", tool.scan_args(interface, ctx.target), authorization=ctx.authorization,
        timeout=ctx.settings.default_timeout_seconds, on_line=ctx.on_line,
    )
    ctx.save_raw(result.stdout, "txt", result.command)
    if result.returncode != 0 and not result.stdout.strip():
        raise ParseError(f"arp-scan failed: {result.stderr.strip()[:200]}")
    return _output(tool.parse(result.stdout))


async def fast_sweep(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Masscan sweep of explicit ports (rate capped)."""
    ports = validate_port_spec(str(params.get("ports") or "22,80,443,445,3389,8080"))
    rate = validate_int(params.get("rate") or 100, low=1, high=100000, name="rate")
    tool = MasscanIntegration(ctx.runner)
    result = await ctx.runner.run(
        "masscan", tool.scan_args(ctx.target, ports, rate), authorization=ctx.authorization,
        timeout=ctx.settings.default_timeout_seconds,
    )
    ctx.save_raw(result.stdout, "json", result.command)
    if result.returncode != 0 and not result.stdout.strip():
        raise ParseError(f"masscan failed: {result.stderr.strip()[:200]}")
    return _output(tool.parse(result.stdout))


async def passive_capture(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Listen on an interface and list the hosts/protocols that were seen."""
    duration = validate_int(params.get("duration") or 30, low=1, high=MAX_DURATION, name="duration")
    tool = TsharkIntegration(ctx.runner)
    result = await ctx.runner.run(
        "tshark", tool.capture_args(ctx.target.value, duration), authorization=ctx.authorization,
        timeout=duration + 30,
    )
    ctx.save_raw(result.stdout, "tsv", result.command)
    if result.returncode != 0 and not result.stdout.strip():
        raise ParseError(f"tshark failed: {result.stderr.strip()[:200]}")
    hosts, protocols = tool.parse(result.stdout)
    output = _output(hosts, {"protocols": protocols})
    output.summary = f"{len(hosts)} host(s) observed, {sum(protocols.values())} packet(s)"
    return output


def register(engine: Engine) -> None:
    """Register every Network Discovery action."""
    iface = frozenset({TargetKind.INTERFACE})
    a, i, p = Intrusiveness.ACTIVE, Intrusiveness.INTRUSIVE, Intrusiveness.PASSIVE
    specs = [
        ("net.host_discovery", "Host discovery (ping sweep)", a, NET_KINDS, ("nmap",), False, host_discovery, (),
         "Find live hosts, MAC addresses and vendors"),
        ("net.arp_scan", "ARP scan (local segment)", a, V4_KINDS, ("arp-scan",), True, arp_scan, ("interface",),
         "Layer-2 discovery of devices on your own LAN"),
        ("net.port_scan", "Port scan", a, NET_KINDS, ("nmap",), False, port_scan, ("ports",),
         "Open TCP ports (top 1000 by default)"),
        ("net.service_os", "Service, version and OS detection", a, NET_KINDS, ("nmap",), True, service_os,
         ("ports",), "Service versions and OS fingerprint"),
        ("net.topology", "Topology (traceroute)", a, NET_KINDS, ("nmap",), True, topology, (),
         "Hop-by-hop paths and subnet map"),
        ("net.fast_sweep", "Fast sweep (masscan, rate-capped)", i, V4_KINDS, ("masscan",), True, fast_sweep,
         ("ports", "rate"), "High-speed sweep; authorized scopes only"),
        ("net.passive_capture", "Passive capture (tshark)", p, iface, ("tshark",), True, passive_capture,
         ("duration",), "Listen only: hosts and protocols seen on an interface"),
    ]
    for ident, title, level, kinds, tools, root, handler, params, description in specs:
        engine.register(
            Action(id=ident, module=MODULE, title=title, intrusiveness=level, target_kinds=kinds,
                   required_tools=tools, requires_root=root, handler=handler, params=params,
                   description=description)
        )

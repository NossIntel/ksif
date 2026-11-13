"""Wi-Fi Security Audit actions (module 04).

Passive only. KSIF lists nearby networks and reads the security they advertise.
It never transmits to a network, never deauthenticates clients, and never
captures traffic or handshakes. Weak-security findings are raised only for the
access points whose BSSID you listed as your own under ``bssids`` in scope.yaml.
"""

from __future__ import annotations

from typing import Any

from core.engine import Action, ActionContext, ActionOutput, Engine
from core.models import Finding, Intrusiveness, TargetKind
from integrations.wifi_tools import IwIntegration, NmcliIntegration, weakest

MODULE = "wifi_audit"
NONE = frozenset({TargetKind.NONE})
INTERFACE = frozenset({TargetKind.INTERFACE})
_WEAK_SEVERITY = {"open": "high", "wep": "high", "wpa1": "medium", "unknown": "low"}


def _mark_owned(networks: list[dict], owned_bssids: set[str]) -> list[dict]:
    for net in networks:
        net["owned"] = net["bssid"].lower() in owned_bssids
    return networks


def _findings(networks: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for net in networks:
        if not net.get("owned"):
            continue  # only audit access points you own
        level = weakest(net["security"])
        severity = _WEAK_SEVERITY.get(level)
        label = net["ssid"] or net["bssid"]
        if severity:
            findings.append(Finding(
                MODULE, "wifi", severity,
                f"Own network '{label}' uses weak security ({net['security']})",
                net["bssid"], evidence=f"security={net['security']} channel={net['channel']}",
                recommendation="Reconfigure the access point to WPA2 (AES) or, preferably, WPA3."))
        if net.get("ssid") == "":
            findings.append(Finding(MODULE, "wifi", "info", "Own network hides its SSID", net["bssid"],
                                    recommendation="Hidden SSIDs add little security; rely on WPA2/WPA3."))
    return findings


async def scan_nmcli(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """List nearby networks with nmcli (no root needed)."""
    tool = NmcliIntegration(ctx.runner)
    rescan = str(params.get("rescan", "")).lower() in ("1", "true", "yes")
    result = await ctx.runner.run("nmcli", tool.scan_args(rescan), authorization=ctx.authorization,
                                  timeout=ctx.settings.default_timeout_seconds, on_line=ctx.on_line)
    ctx.save_raw(result.stdout, "txt", result.command)
    networks = _mark_owned(tool.parse(result.stdout), {b.lower() for b in ctx.scope.bssids})
    return _output(networks)


async def scan_iw(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Scan on a specific interface with iw (needs root)."""
    tool = IwIntegration(ctx.runner)
    result = await ctx.runner.run("iw", tool.scan_args(ctx.target.value), authorization=ctx.authorization,
                                  timeout=ctx.settings.default_timeout_seconds, on_line=ctx.on_line)
    ctx.save_raw(result.stdout, "txt", result.command)
    networks = _mark_owned(tool.parse(result.stdout), {b.lower() for b in ctx.scope.bssids})
    return _output(networks)


async def audit(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Review stored networks and flag weak security on the ones you own."""
    rows = ctx.db.list_rows("wifi_networks", None, "owned DESC, ssid")
    networks = [dict(r, owned=bool(r["owned"])) for r in rows]
    findings = _findings(networks)
    owned = [n for n in networks if n["owned"]]
    by_security: dict[str, int] = {}
    for net in networks:
        by_security[net["security"]] = by_security.get(net["security"], 0) + 1
    return ActionOutput(findings=findings,
                        summary=f"{len(networks)} network(s) stored, {len(owned)} owned, "
                                f"{len(findings)} finding(s)",
                        data={"by_security": by_security, "owned": [n["ssid"] or n["bssid"] for n in owned]})


def _output(networks: list[dict]) -> ActionOutput:
    findings = _findings(networks)
    owned = sum(1 for n in networks if n.get("owned"))
    by_band: dict[str, int] = {}
    for net in networks:
        by_band[net["band"] or "?"] = by_band.get(net["band"] or "?", 0) + 1
    return ActionOutput(findings=findings, wifi=networks,
                        summary=f"{len(networks)} network(s), {owned} owned, {len(findings)} finding(s)",
                        data={"by_band": by_band})


def _cmd(binary: str, args: list[str]) -> str:
    return binary + " " + " ".join(args)


def _pv_scan(t, p):
    rescan = str(p.get("rescan", "")).lower() in ("1", "true", "yes")
    return [_cmd("nmcli", NmcliIntegration(None).scan_args(rescan))]


def _pv_scan_iw(t, p):
    return [_cmd("iw", IwIntegration(None).scan_args(t.value))]


def _pv_audit(t, p):
    return ["(built-in) reads the Wi-Fi networks already stored; flags weak security on your own access points"]


def register(engine: Engine) -> None:
    """Register every Wi-Fi audit action (all passive)."""
    p = Intrusiveness.PASSIVE
    specs = [
        ("wifi.scan", "Scan nearby networks (nmcli)", NONE, ("nmcli",), False, scan_nmcli, ("rescan",),
         "Passive listing of nearby Wi-Fi networks", _pv_scan,
         "No target, no root. Lists nearby networks (SSID, BSSID, channel, security). "
         "Optional 'rescan' param (yes forces a fresh scan)."),
        ("wifi.scan_iw", "Scan on interface (iw)", INTERFACE, ("iw",), True, scan_iw, (),
         "Passive scan on a specific interface", _pv_scan_iw,
         "Needs root and an interface in scope. Passive scan on that interface. Enter e.g.  wlan0"),
        ("wifi.audit", "Audit stored networks", NONE, (), False, audit, (),
         "Flag weak security on access points you own", _pv_audit,
         "No target. Reviews stored networks and flags weak security (open/WEP/WPA1) on your own BSSIDs."),
    ]
    for ident, title, kinds, tools, root, handler, prms, desc, preview, usage in specs:
        engine.register(Action(id=ident, module=MODULE, title=title, intrusiveness=p, target_kinds=kinds,
                               required_tools=tools, requires_root=root, handler=handler, params=prms,
                               description=desc, preview=preview, usage=usage))

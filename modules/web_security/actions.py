"""Web Security Assessment actions (module 03).

Targets must be in your authorized scope. Fingerprinting and the header check
are light; nikto and nuclei are active scans; wpscan is restricted to the
WordPress sites you listed as your own in scope.yaml.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.engine import Action, ActionContext, ActionOutput, Engine
from core.http import NetworkError
from core.models import Finding, Intrusiveness, TargetKind
from integrations.base import ParseError, ToolIntegration
from integrations.web_tools import (
    NiktoIntegration,
    NucleiIntegration,
    WhatWebIntegration,
    WpscanIntegration,
)
from modules.web_security.headers import analyze_headers

MODULE = "web_security"
WEB = frozenset({TargetKind.DOMAIN, TargetKind.URL, TargetKind.IPV4, TargetKind.IPV6})
WEB_URL = frozenset({TargetKind.DOMAIN, TargetKind.URL})
_SEV = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5, "unknown": 1.0}


async def _run(ctx: ActionContext, tool: ToolIntegration, args: list[str], ext: str) -> str:
    result = await ctx.runner.run(
        tool.binary, args, authorization=ctx.authorization,
        timeout=ctx.settings.default_timeout_seconds, on_line=ctx.on_line,
    )
    ctx.save_raw(result.stdout + ("\n--- stderr ---\n" + result.stderr if result.stderr else ""),
                 ext, result.command)
    return result.stdout, result.returncode


def _host_of(ctx: ActionContext) -> str:
    target = ctx.target
    if target.kind is TargetKind.URL:
        return (urlsplit(target.value).hostname or "").lower()
    return target.value.lower()


async def fingerprint(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Identify server, frameworks and technologies with WhatWeb."""
    tool = WhatWebIntegration(ctx.runner)
    stdout, _ = await _run(ctx, tool, tool.scan_args(ctx.target), "txt")
    tech = tool.parse(stdout)
    records = [{"kind": "technology", "name": k, "value": v or "(detected)", "source": "whatweb"}
               for k, v in tech.items()]
    findings = []
    for name, value in tech.items():
        if name in ("HTTPServer", "PoweredBy", "X-Powered-By") and any(c.isdigit() for c in value):
            findings.append(Finding(MODULE, "fingerprint", "low", f"Version disclosed: {name}",
                                    ctx.target.value, evidence=f"{name}[{value}]",
                                    recommendation="Hide product versions in HTTP responses."))
    return ActionOutput(findings=findings, osint=records,
                        summary=f"{len(tech)} technology marker(s)", data={"technologies": tech})


async def security_headers(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Check HTTP security headers (no external tool)."""
    url = ctx.http.base_url(ctx.authorization, "https")
    is_https = url.startswith("https")
    try:
        response = ctx.http.fetch(url, ctx.authorization)
    except NetworkError:
        if is_https and ctx.target.kind is not TargetKind.URL:
            url = ctx.http.base_url(ctx.authorization, "http")
            is_https = False
            response = ctx.http.fetch(url, ctx.authorization)
        else:
            raise
    findings = analyze_headers(response.final_url, response.status, response.headers, is_https)
    present = {k: v for k, v in response.headers.items()
               if k in ("server", "x-powered-by", "content-security-policy",
                        "strict-transport-security", "x-frame-options", "x-content-type-options")}
    return ActionOutput(findings=findings,
                        summary=f"HTTP {response.status}, {len(findings)} header finding(s)",
                        data={"status": response.status, "headers": present})


async def nikto_scan(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Scan for known web-server misconfigurations with nikto."""
    tool = NiktoIntegration(ctx.runner)
    stdout, _ = await _run(ctx, tool, tool.scan_args(ctx.target), "txt")
    items = tool.parse(stdout)
    findings = [Finding(MODULE, "nikto", _nikto_severity(i["message"]),
                        i["message"][:120], ctx.target.value, evidence=i["message"],
                        recommendation="Review this server exposure and remove or restrict it.")
                for i in items]
    return ActionOutput(findings=findings, summary=f"nikto: {len(items)} item(s)")


def _nikto_severity(message: str) -> str:
    low = message.lower()
    if any(w in low for w in ("osvdb", "sql", "xss", "traversal", "disclosure", "default account")):
        return "medium"
    if any(w in low for w in ("outdated", "cve-")):
        return "high"
    return "low"


async def nuclei_scan(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Run nuclei templates against the target."""
    tool = NucleiIntegration(ctx.runner)
    severities = str(params.get("severity") or "low,medium,high,critical")
    stdout, _ = await _run(ctx, tool, tool.scan_args(ctx.target, severities), "jsonl")
    matches = tool.parse(stdout)
    findings, vulns = [], []
    for match in matches:
        findings.append(Finding(MODULE, "nuclei", match["severity"], match["name"] or match["template"],
                                match["matched"] or ctx.target.value,
                                evidence=f"template {match['template']}",
                                recommendation="Verify and remediate the detected issue."))
        for cve in match["cves"]:
            vulns.append({"cve_id": cve, "host": _host_of(ctx), "product": match["template"],
                          "severity": match["severity"], "summary": match["name"],
                          "priority": _SEV.get(match["severity"], 1.0), "source": "nuclei"})
    return ActionOutput(findings=findings, vulnerabilities=vulns,
                        summary=f"nuclei: {len(matches)} match(es)")


async def wpscan_scan(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Assess a WordPress site you own (must be listed in scope wordpress_sites)."""
    host = _host_of(ctx)
    owned = {s.lower() for s in ctx.scope.wordpress_sites}
    if host not in owned:
        raise PermissionError(
            f"{host} is not listed under 'wordpress_sites' in scope.yaml; wpscan is owner-only")
    import os
    token = os.environ.get("WPSCAN_API_TOKEN") or None
    tool = WpscanIntegration(ctx.runner)
    stdout, _ = await _run(ctx, tool, tool.scan_args(ctx.target, token), "json")
    data = tool.parse(stdout)
    findings, vulns = [], []
    if data["version"]:
        findings.append(Finding(MODULE, "wordpress", "info", f"WordPress {data['version']} detected",
                                ctx.target.value, recommendation="Keep WordPress core up to date."))
    for group, items in (("core", data["core_vulnerabilities"]),
                         *[("plugin:" + p["name"], p["vulnerabilities"]) for p in data["plugins"]]):
        for vuln in items:
            title = vuln.get("title", "WordPress vulnerability")
            refs = vuln.get("references", {}) or {}
            cves = [f"CVE-{c}" if not str(c).upper().startswith("CVE") else str(c).upper()
                    for c in refs.get("cve", [])]
            findings.append(Finding(MODULE, "wordpress", "high", f"{group}: {title}"[:120],
                                    ctx.target.value, evidence=", ".join(cves),
                                    recommendation="Update the affected component."))
            for cve in cves:
                vulns.append({"cve_id": cve, "host": host, "product": group, "severity": "high",
                              "summary": title, "priority": 7.5, "source": "wpscan"})
    return ActionOutput(findings=findings, vulnerabilities=vulns,
                        summary=f"wpscan: WordPress {data['version'] or '?'}, {len(findings)} finding(s)")


def _cmd(binary: str, args: list[str]) -> str:
    return binary + " " + " ".join(args)


def _pv_fingerprint(t, p):
    return [_cmd("whatweb", WhatWebIntegration(None).scan_args(t))]


def _pv_headers(t, p):
    url = t.value if t.kind is TargetKind.URL else f"https://{t.value}/"
    return [f"(built-in) GET {url} and inspect HSTS, CSP, X-Frame-Options, X-Content-Type-Options, cookies"]


def _pv_nikto(t, p):
    return [_cmd("nikto", NiktoIntegration(None).scan_args(t))]


def _pv_nuclei(t, p):
    return [_cmd("nuclei", NucleiIntegration(None).scan_args(t, p.get("severity") or "low,medium,high,critical"))]


def _pv_wpscan(t, p):
    return [_cmd("wpscan", WpscanIntegration(None).scan_args(t)) + "   (--api-token added if WPSCAN_API_TOKEN is set)"]


def register(engine: Engine) -> None:
    """Register every Web Security action."""
    a = Intrusiveness.ACTIVE
    specs = [
        ("web.fingerprint", "Technology fingerprint (WhatWeb)", a, WEB, ("whatweb",), fingerprint, (),
         "Identify server, frameworks and technologies", "", _pv_fingerprint,
         "Enter a domain, URL or IP. Identifies the server, frameworks and libraries in use."),
        ("web.headers", "Security header check", a, WEB, (), security_headers, (),
         "HTTP security headers (HSTS, CSP, cookies)", "", _pv_headers,
         "Enter a domain or URL. No external tool. Checks the HTTP security headers."),
        ("web.nikto", "Server misconfiguration scan (nikto)", a, WEB, ("nikto",), nikto_scan, (),
         "Known web-server issues and exposed files", "", _pv_nikto,
         "Enter a domain or URL. Scans for known server issues and exposed files (noisy)."),
        ("web.nuclei", "Template scan (nuclei)", a, WEB, ("nuclei",), nuclei_scan, ("severity",),
         "Community templates for known issues", "", _pv_nuclei,
         "Enter a target; optional 'severity' (default low,medium,high,critical). Maps CVEs to module 06."),
        ("web.wpscan", "WordPress assessment (wpscan)", a, WEB_URL, ("wpscan",), wpscan_scan, (),
         "WordPress core/plugin issues (owned sites only)",
         "I confirm this WordPress site is mine or I am authorized to assess it", _pv_wpscan,
         "Only for hosts listed under 'wordpress_sites' in scope.yaml. Enumerates core/plugins/users."),
    ]
    for ident, title, level, kinds, tools, handler, prms, desc, consent, preview, usage in specs:
        engine.register(Action(id=ident, module=MODULE, title=title, intrusiveness=level,
                               target_kinds=kinds, required_tools=tools, requires_root=False,
                               handler=handler, params=prms, description=desc, consent=consent,
                               preview=preview, usage=usage))

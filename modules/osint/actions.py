"""OSINT Intelligence actions (module 02).

Every action here is passive: it collects information that is already public
(registries, DNS, certificate transparency, search engines) about a domain
that is in your authorized scope.
"""

from __future__ import annotations

from typing import Any

from core.engine import Action, ActionContext, ActionOutput, Engine
from core.http import NetworkError, days_until
from core.models import Finding, Intrusiveness, TargetKind
from integrations.base import ToolIntegration
from integrations.osint_tools import (
    AmassIntegration,
    DigIntegration,
    SubfinderIntegration,
    TheHarvesterIntegration,
    WhoisIntegration,
)

MODULE = "osint"
DOMAIN = frozenset({TargetKind.DOMAIN})
DOMAIN_OR_URL = frozenset({TargetKind.DOMAIN, TargetKind.URL})
NONE = frozenset({TargetKind.NONE})
WEAK_TLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}


async def _run(ctx: ActionContext, tool: ToolIntegration, args: list[str], ext: str) -> str:
    result = await ctx.runner.run(
        tool.binary, args, authorization=ctx.authorization,
        timeout=ctx.settings.default_timeout_seconds, on_line=ctx.on_line,
    )
    ctx.save_raw(result.stdout + ("\n--- stderr ---\n" + result.stderr if result.stderr else ""),
                 ext, result.command)
    return result.stdout


async def whois_lookup(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Registration data: registrar, dates, name servers."""
    tool = WhoisIntegration(ctx.runner)
    fields = tool.parse(await _run(ctx, tool, tool.query_args(ctx.target), "txt"))
    records, findings = [], []
    domain = ctx.target.value
    for key, value in fields.items():
        for item in (value if isinstance(value, list) else [value]):
            records.append({"kind": "whois", "name": key, "value": item, "source": "whois"})
    expires = fields.get("expires")
    if isinstance(expires, str):
        left = days_until_iso(expires)
        if left is not None and left < 30:
            findings.append(Finding(
                MODULE, "domain", "medium" if left >= 0 else "high",
                "Domain registration expires soon" if left >= 0 else "Domain registration expired",
                domain, description=f"Registry expiry in {left} day(s): {expires}",
                recommendation="Renew the domain registration to avoid loss or hijacking."))
    return ActionOutput(findings=findings, osint=records,
                        summary=f"{len(records)} whois field(s)", data={"whois": fields})


async def dns_records(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """A, AAAA, MX, NS, TXT, SOA and CNAME records."""
    tool = DigIntegration(ctx.runner)
    records_by_type = tool.parse(await _run(ctx, tool, tool.query_args(ctx.target), "txt"))
    records, findings = [], []
    for rtype, values in records_by_type.items():
        for value in values:
            records.append({"kind": "dns", "name": rtype, "value": value, "source": "dig"})
    for txt in records_by_type.get("TXT", []):
        low = txt.lower()
        if "v=spf1" in low and ("+all" in low or ("all" in low and "-all" not in low and "~all" not in low)):
            findings.append(Finding(MODULE, "dns", "low", "Weak SPF policy", ctx.target.value,
                                    evidence=txt, recommendation="Use '-all' (or '~all') in the SPF record."))
    if not any(r.lower().startswith("v=dmarc1") for r in _dmarc(records_by_type)):
        pass  # DMARC lives on _dmarc.<domain>; not queried here, so no finding
    return ActionOutput(findings=findings, osint=records,
                        summary=f"{sum(len(v) for v in records_by_type.values())} DNS record(s)",
                        data=records_by_type)


def _dmarc(records: dict[str, list[str]]) -> list[str]:
    return records.get("TXT", [])


async def subdomains(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Passive subdomain discovery (subfinder, falling back to amass)."""
    subfinder, amass = SubfinderIntegration(ctx.runner), AmassIntegration(ctx.runner)
    tool, args = (subfinder, None)
    if subfinder.is_available():
        tool, args = subfinder, subfinder.query_args(ctx.target)
    elif amass.is_available():
        tool, args = amass, amass.query_args(ctx.target)
    else:
        raise RuntimeError("neither subfinder nor amass is installed")
    found = tool.parse(await _run(ctx, tool, args, "txt"), ctx.target.value)
    records = [{"kind": "subdomain", "name": s, "value": s, "source": tool.binary} for s in found]
    return ActionOutput(osint=records, summary=f"{len(found)} subdomain(s) via {tool.binary}",
                        data={"subdomains": found})


async def tls_certificate(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Inspect the TLS certificate and negotiated protocol (no external tool)."""
    try:
        port = int(str(params.get("port") or 443))
    except ValueError:
        port = 443
    try:
        info = ctx.http.tls_info(ctx.authorization, port)
    except NetworkError as exc:
        raise RuntimeError(str(exc)) from exc
    if info.error:
        raise RuntimeError(f"TLS inspection failed: {info.error}")
    host = ctx.target.value
    records = [
        {"kind": "tls", "name": "protocol", "value": info.protocol, "source": "tls"},
        {"kind": "tls", "name": "cipher", "value": info.cipher, "source": "tls"},
        {"kind": "tls", "name": "issuer", "value": info.issuer, "source": "tls"},
        {"kind": "tls", "name": "not_after", "value": info.not_after, "source": "tls"},
    ]
    records += [{"kind": "tls", "name": "san", "value": s, "source": "tls"} for s in info.san]
    findings = []
    if info.protocol in WEAK_TLS:
        findings.append(Finding(MODULE, "tls", "high", f"Weak TLS protocol {info.protocol}", host,
                                evidence=f"{info.protocol} / {info.cipher}",
                                recommendation="Disable TLS 1.1 and older; require TLS 1.2+."))
    left = days_until(info.not_after) if info.not_after else None
    if left is not None and left < 0:
        findings.append(Finding(MODULE, "tls", "high", "TLS certificate expired", host,
                                evidence=f"notAfter {info.not_after}", recommendation="Renew the certificate."))
    elif left is not None and left < 21:
        findings.append(Finding(MODULE, "tls", "medium", "TLS certificate expires soon", host,
                                evidence=f"{left} day(s) left ({info.not_after})",
                                recommendation="Renew the certificate before it expires."))
    return ActionOutput(findings=findings, osint=records,
                        summary=f"TLS {info.protocol}, cert valid until {info.not_after or '?'}",
                        data={"tls": info.__dict__})


async def harvester(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Public emails and hostnames from search engines and certificate logs."""
    tool = TheHarvesterIntegration(ctx.runner)
    sources = str(params.get("sources") or "crtsh,bing,duckduckgo")
    data = tool.parse(await _run(ctx, tool, tool.query_args(ctx.target, sources), "txt"), ctx.target.value)
    records = [{"kind": "email", "name": e, "value": e, "source": "theHarvester"} for e in data["emails"]]
    records += [{"kind": "host", "name": h, "value": h, "source": "theHarvester"} for h in data["hosts"]]
    findings = []
    if data["emails"]:
        findings.append(Finding(MODULE, "exposure", "info",
                                f"{len(data['emails'])} public email address(es) found", ctx.target.value,
                                evidence=", ".join(data["emails"][:10]),
                                recommendation="Review which addresses need to be public; watch for phishing."))
    return ActionOutput(findings=findings, osint=records,
                        summary=f"{len(data['emails'])} email(s), {len(data['hosts'])} host(s)", data=data)


async def correlate(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Summarise all stored OSINT and cross-reference it with discovered hosts."""
    osint = ctx.db.list_rows("osint_records", None, "kind, name")
    by_kind: dict[str, int] = {}
    for row in osint:
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
    subs = [r["value"] for r in osint if r["kind"] == "subdomain"]
    hosts = {h.address for h in ctx.db.list_hosts()}
    findings = []
    if by_kind.get("subdomain", 0) > 20:
        findings.append(Finding(MODULE, "surface", "info", "Large external attack surface", "scope",
                                evidence=f"{by_kind['subdomain']} subdomains discovered",
                                recommendation="Confirm each subdomain is intended to be exposed."))
    return ActionOutput(findings=findings,
                        summary=f"{len(osint)} OSINT record(s) across {len(by_kind)} kind(s)",
                        data={"by_kind": by_kind, "subdomains": subs[:200], "known_hosts": sorted(hosts)[:200]})


def days_until_iso(value: str) -> int | None:
    """Days until a whois date string (several common formats)."""
    from datetime import UTC, datetime
    value = value.strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d"):
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return (parsed - datetime.now(UTC)).days
    return None


def _cmd(binary: str, args: list[str]) -> str:
    return binary + " " + " ".join(args)


def _pv_whois(t, p):
    return [_cmd("whois", WhoisIntegration(None).query_args(t))]


def _pv_dns(t, p):
    return [_cmd("dig", DigIntegration(None).query_args(t))]


def _pv_subdomains(t, p):
    return [_cmd("subfinder", SubfinderIntegration(None).query_args(t)),
            _cmd("amass", AmassIntegration(None).query_args(t)) + "   (used if subfinder is absent)"]


def _pv_harvester(t, p):
    return [_cmd("theHarvester", TheHarvesterIntegration(None).query_args(t, p.get("sources") or "crtsh,bing,duckduckgo"))]


def _pv_tls(t, p):
    return [f"(built-in) TLS handshake to {t.value}:{p.get('port') or 443}; reads certificate, protocol and expiry"]


def _pv_correlate(t, p):
    return ["(built-in) reads the OSINT records already stored in the database; runs no external tool"]


def register(engine: Engine) -> None:
    """Register every OSINT action."""
    p = Intrusiveness.PASSIVE
    specs = [
        ("osint.whois", "WHOIS lookup", DOMAIN, ("whois",), False, whois_lookup, (),
         "Domain registration data", _pv_whois,
         "Enter a domain. Shows registrar, creation/expiry dates and name servers."),
        ("osint.dns", "DNS records", DOMAIN, ("dig",), False, dns_records, (),
         "A, AAAA, MX, NS, TXT, SOA records", _pv_dns,
         "Enter a domain. Lists DNS records and flags a weak SPF policy."),
        ("osint.subdomains", "Subdomain discovery (passive)", DOMAIN, ("subfinder", "amass"), False,
         subdomains, (), "Passive subdomain enumeration", _pv_subdomains,
         "Enter a domain. Uses subfinder (or amass) to find subdomains from public sources."),
        ("osint.tls_cert", "TLS certificate inspection", DOMAIN_OR_URL, (), False, tls_certificate,
         ("port",), "Certificate, protocol and expiry", _pv_tls,
         "Enter a domain or https URL. No external tool. Flags weak TLS and expiring certificates."),
        ("osint.harvester", "Public emails and hosts", DOMAIN, ("theHarvester",), False, harvester,
         ("sources",), "Emails and hosts from public sources", _pv_harvester,
         "Enter a domain; optional 'sources' param (default crtsh,bing,duckduckgo)."),
        ("osint.correlate", "Correlate stored OSINT", NONE, (), False, correlate, (),
         "Summarise and cross-reference collected intelligence", _pv_correlate,
         "No target. Summarises everything OSINT has stored so far."),
    ]
    pt = {
        "osint.whois": ("Consulta WHOIS", "Dados de registro do domínio",
            "Informe um domínio. Mostra registrador, datas de criação/expiração e servidores de nomes."),
        "osint.dns": ("Registros DNS", "Registros A, AAAA, MX, NS, TXT, SOA",
            "Informe um domínio. Lista os registros DNS e sinaliza política SPF fraca."),
        "osint.subdomains": ("Descoberta de subdomínios (passiva)", "Enumeração passiva de subdomínios",
            "Informe um domínio. Usa subfinder (ou amass) para achar subdomínios em fontes públicas."),
        "osint.tls_cert": ("Inspeção de certificado TLS", "Certificado, protocolo e validade",
            "Informe um domínio ou URL https. Sem ferramenta externa. Sinaliza TLS fraco e certificado vencendo."),
        "osint.harvester": ("E-mails e hosts públicos", "E-mails e hosts em fontes públicas",
            "Informe um domínio; parâmetro opcional de fontes (padrão crtsh,bing,duckduckgo)."),
        "osint.correlate": ("Correlacionar OSINT armazenado", "Resume e cruza a inteligência coletada",
            "Sem alvo. Resume tudo que o OSINT já armazenou."),
    }
    for ident, title, kinds, tools, root, handler, prms, desc, preview, usage in specs:
        tpt, dpt, upt = pt.get(ident, ("", "", ""))
        engine.register(Action(id=ident, module=MODULE, title=title, intrusiveness=p, target_kinds=kinds,
                               required_tools=tools, requires_root=root, handler=handler, params=prms,
                               description=desc, any_tool=len(tools) > 1, preview=preview, usage=usage,
                               title_pt=tpt, description_pt=dpt, usage_pt=upt))

"""OSINT tool integrations: whois, dig, subfinder, amass, theHarvester.

All of these gather information that is already public. They are passive: they
query registries, DNS and public sources about a domain in scope. None of them
touches the target's own infrastructure with intrusive traffic.
"""

from __future__ import annotations

import re

from core.models import Target, TargetKind
from core.validator import ValidationError, is_valid_domain
from integrations.base import ToolIntegration

_DOMAIN_KINDS = (TargetKind.DOMAIN,)


def _require_domain(target: Target) -> str:
    if target.kind not in _DOMAIN_KINDS:
        raise ValidationError("this OSINT action needs a domain target")
    return target.value


class WhoisIntegration(ToolIntegration):
    """Registration data for a domain via ``whois``."""

    binary = "whois"
    install_hint = "sudo apt install whois"
    version_pattern = r"Version (\d+\.\d+(?:\.\d+)*)"

    _FIELDS = {
        "registrar": re.compile(r"^\s*Registrar:\s*(.+?)\s*$", re.I),
        "registrant_org": re.compile(r"^\s*Registrant Organization:\s*(.+?)\s*$", re.I),
        "created": re.compile(r"^\s*(?:Creation Date|created):\s*(.+?)\s*$", re.I),
        "expires": re.compile(r"^\s*(?:Registry Expiry Date|Expiry Date|paid-till):\s*(.+?)\s*$", re.I),
        "updated": re.compile(r"^\s*Updated Date:\s*(.+?)\s*$", re.I),
    }
    _NS = re.compile(r"^\s*Name Server:\s*(\S+)", re.I)

    def query_args(self, target: Target) -> list[str]:
        return [_require_domain(target)]

    def parse(self, output: str) -> dict[str, list[str] | str]:
        """Return a dict of selected whois fields and all name servers."""
        result: dict[str, list[str] | str] = {}
        nameservers: list[str] = []
        for line in output.splitlines():
            match = self._NS.match(line)
            if match:
                ns = match.group(1).lower().rstrip(".")
                if ns not in nameservers:
                    nameservers.append(ns)
            for key, pattern in self._FIELDS.items():
                found = pattern.match(line)
                if found and key not in result:
                    result[key] = found.group(1)
        if nameservers:
            result["nameservers"] = nameservers
        return result


class DigIntegration(ToolIntegration):
    """DNS records via ``dig``."""

    binary = "dig"
    install_hint = "sudo apt install dnsutils"
    version_pattern = r"DiG (\d+\.\d+(?:\.\d+)*)"
    RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME")

    def query_args(self, target: Target) -> list[str]:
        domain = _require_domain(target)
        return ["+noall", "+answer", "+nocomments", domain, *self.RECORD_TYPES]

    def parse(self, output: str) -> dict[str, list[str]]:
        """Group answer lines by record type."""
        records: dict[str, list[str]] = {}
        for line in output.splitlines():
            parts = line.split("\t") if "\t" in line else line.split()
            parts = [p for p in parts if p]
            if len(parts) < 5:
                continue
            rtype, data = parts[3], " ".join(parts[4:]).strip()
            if rtype in self.RECORD_TYPES and data:
                records.setdefault(rtype, [])
                if data not in records[rtype]:
                    records[rtype].append(data)
        return records


class _SubdomainTool(ToolIntegration):
    """Shared subdomain parsing: keep lines that are subdomains of the target."""

    def parse(self, output: str, domain: str) -> list[str]:
        suffix = "." + domain.lower()
        found: list[str] = []
        for line in output.splitlines():
            candidate = line.strip().lower().rstrip(".")
            candidate = candidate.split()[-1] if candidate else ""
            if (candidate == domain.lower() or candidate.endswith(suffix)) and is_valid_domain(candidate):
                if candidate not in found:
                    found.append(candidate)
        return sorted(found)


class SubfinderIntegration(_SubdomainTool):
    """Passive subdomain discovery via ``subfinder``."""

    binary = "subfinder"
    install_hint = "sudo apt install subfinder"
    probe_arg = "-version"
    version_pattern = r"(\d+\.\d+\.\d+)"

    def query_args(self, target: Target) -> list[str]:
        return ["-silent", "-all", "-d", _require_domain(target)]


class AmassIntegration(_SubdomainTool):
    """Passive subdomain enumeration via ``amass``."""

    binary = "amass"
    install_hint = "sudo apt install amass"
    probe_arg = "-version"
    version_pattern = r"v?(\d+\.\d+\.\d+)"

    def query_args(self, target: Target) -> list[str]:
        return ["enum", "-passive", "-silent", "-d", _require_domain(target)]


class TheHarvesterIntegration(ToolIntegration):
    """Public emails and hosts via ``theHarvester`` (passive sources)."""

    binary = "theHarvester"
    install_hint = "sudo apt install theharvester"
    probe_arg = "-h"
    version_pattern = r"(\d+\.\d+(?:\.\d+)*)"

    def query_args(self, target: Target, sources: str = "crtsh,bing,duckduckgo") -> list[str]:
        safe = re.sub(r"[^a-z0-9,]", "", sources.lower()) or "crtsh"
        return ["-d", _require_domain(target), "-b", safe]

    _EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

    def parse(self, output: str, domain: str) -> dict[str, list[str]]:
        """Extract emails and hostnames belonging to the domain."""
        suffix = "." + domain.lower()
        emails = sorted({e.lower() for e in self._EMAIL.findall(output)
                         if e.lower().endswith(suffix) or e.lower().endswith("@" + domain.lower())})
        hosts: list[str] = []
        for line in output.splitlines():
            token = line.strip().lower().rstrip(".")
            token = token.split(":")[0].strip()
            if (token == domain.lower() or token.endswith(suffix)) and is_valid_domain(token):
                if token not in hosts:
                    hosts.append(token)
        return {"emails": emails, "hosts": sorted(hosts)}

    def parse_version(self, output: str) -> str | None:
        match = re.search(r"theHarvester\s+(\d+\.\d+(?:\.\d+)*)", output) or re.search(self.version_pattern, output)
        return match.group(1) if match else None

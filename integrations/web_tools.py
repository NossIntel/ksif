"""Web assessment tool integrations: whatweb, nikto, nuclei, wpscan.

These contact a web target that is in your authorized scope. whatweb and the
header check are light; nikto and nuclei send many requests; wpscan is for
WordPress sites you have marked as your own.
"""

from __future__ import annotations

import json
import re

from core.models import Target, TargetKind
from integrations.base import ParseError, ToolIntegration

_WEB_KINDS = (TargetKind.DOMAIN, TargetKind.URL, TargetKind.IPV4, TargetKind.IPV6)


def _as_url(target: Target) -> str:
    """The value to hand a web tool.

    For a URL target it is the full URL. For a domain or IP it is the bare host
    (the tools add the scheme themselves). Returning the bare host keeps the
    authorized target value present verbatim in the command, as the subprocess
    manager requires.
    """
    return target.value


class WhatWebIntegration(ToolIntegration):
    """Technology fingerprinting via ``whatweb``."""

    binary = "whatweb"
    install_hint = "sudo apt install whatweb"
    version_pattern = r"WhatWeb version (\d+\.\d+(?:\.\d+)*)"

    def scan_args(self, target: Target) -> list[str]:
        return ["--color=never", "--no-errors", "-a", "3", _as_url(target)]

    _PLUGIN = re.compile(r"([A-Za-z0-9\-_]+)(?:\[([^\]]*)\])?")

    def parse(self, output: str) -> dict[str, str]:
        """Return {plugin: value} from the WhatWeb summary line(s)."""
        technologies: dict[str, str] = {}
        for line in output.splitlines():
            if "[" not in line and "200 OK" not in line and "http" not in line.lower():
                continue
            body = re.sub(r"^\S+\s+\[[^\]]*\]\s*", "", line.strip())
            for name, value in self._PLUGIN.findall(body):
                if name and name[0].isalpha() and name not in ("http", "https"):
                    technologies.setdefault(name, value or "")
        return technologies


class NiktoIntegration(ToolIntegration):
    """Web server misconfiguration scan via ``nikto``."""

    binary = "nikto"
    install_hint = "sudo apt install nikto"
    probe_arg = "-Version"
    version_pattern = r"(\d+\.\d+\.\d+)"

    def scan_args(self, target: Target) -> list[str]:
        return ["-host", _as_url(target), "-nointeractive", "-ask", "no", "-maxtime", "120s"]

    _ITEM = re.compile(r"^\+\s+(.*)$")

    def parse(self, output: str) -> list[dict[str, str]]:
        """Return findings from the ``+`` lines of nikto's report."""
        items: list[dict[str, str]] = []
        for line in output.splitlines():
            match = self._ITEM.match(line.strip())
            if not match:
                continue
            text = match.group(1).strip()
            low = text.lower()
            if low.startswith(("target ", "start time", "server:", "retrieved", "ssl info", "end time")):
                continue
            if "host(s) tested" in low or "requests:" in low:
                continue
            uri = ""
            uri_match = re.search(r"(/\S*)", text)
            if uri_match:
                uri = uri_match.group(1)
            items.append({"uri": uri, "message": text})
        return items

    def parse_version(self, output: str) -> str | None:
        match = re.search(r"Nikto v?(\d+\.\d+\.\d+)", output) or re.search(self.version_pattern, output)
        return match.group(1) if match else None


class NucleiIntegration(ToolIntegration):
    """Template-based detection via ``nuclei`` (JSONL output)."""

    binary = "nuclei"
    install_hint = "sudo apt install nuclei"
    probe_arg = "-version"
    version_pattern = r"(\d+\.\d+\.\d+)"

    VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")

    def scan_args(self, target: Target, severities: str = "low,medium,high,critical") -> list[str]:
        tokens = [t for t in re.split(r"[^a-z]+", severities.lower()) if t in self.VALID_SEVERITIES]
        safe = ",".join(dict.fromkeys(tokens)) or "medium,high,critical"
        return ["-u", _as_url(target), "-jsonl", "-silent", "-no-color", "-severity", safe]

    def parse(self, output: str) -> list[dict[str, str]]:
        """Parse JSONL: one object per match."""
        results: list[dict[str, str]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ParseError(f"nuclei JSONL is malformed: {exc}") from exc
            info = obj.get("info", {})
            cves = [c.upper() for c in (info.get("classification", {}) or {}).get("cve-id", []) or []]
            results.append({
                "template": obj.get("template-id", ""), "name": info.get("name", ""),
                "severity": (info.get("severity") or "info").lower(),
                "matched": obj.get("matched-at", obj.get("host", "")),
                "cves": cves,
            })
        return results


class WpscanIntegration(ToolIntegration):
    """WordPress assessment via ``wpscan`` (JSON output). Owned sites only."""

    binary = "wpscan"
    install_hint = "sudo gem install wpscan"
    version_pattern = r"(\d+\.\d+\.\d+)"

    def scan_args(self, target: Target, api_token: str | None = None) -> list[str]:
        if target.kind not in (TargetKind.URL, TargetKind.DOMAIN):
            raise ValueError("wpscan needs a URL or domain target")
        url = _as_url(target)
        args = ["--url", url, "--format", "json", "--no-banner", "--random-user-agent",
                "--enumerate", "vp,vt,u"]
        if api_token:
            args += ["--api-token", api_token]
        return args

    def parse(self, output: str) -> dict[str, object]:
        """Parse the wpscan JSON report into version, findings and plugins."""
        start = output.find("{")
        if start < 0:
            raise ParseError("wpscan produced no JSON")
        try:
            data = json.loads(output[start:])
        except json.JSONDecodeError as exc:
            raise ParseError(f"wpscan JSON is malformed: {exc}") from exc
        version = (data.get("version") or {}).get("number")
        core_vulns = (data.get("version") or {}).get("vulnerabilities") or []
        plugins = []
        for name, plugin in (data.get("plugins") or {}).items():
            plugins.append({
                "name": name, "version": (plugin.get("version") or {}).get("number"),
                "vulnerabilities": plugin.get("vulnerabilities") or [],
            })
        interesting = [f.get("to_s") or f.get("url", "") for f in data.get("interesting_findings") or []]
        return {"version": version, "core_vulnerabilities": core_vulns, "plugins": plugins,
                "interesting": interesting}

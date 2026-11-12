"""Collects stored results into one report document (a plain dict)."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Any

from core.config import Scope, Settings
from core.database import Database, utc_now
from core.models import SEVERITIES
from modules.network_discovery.topology import subnet_map

_RISK_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}


def _overall_risk(counts: Counter[str]) -> str:
    for level in ("critical", "high", "medium", "low"):
        if counts.get(level):
            return level
    return "informational"


def _executive_summary(summary: dict[str, Any], engagement: str) -> str:
    parts = [
        f"This assessment{' (' + engagement + ')' if engagement else ''} covered "
        f"{summary['operations_total']} operation(s) and identified {summary['hosts_total']} host(s) "
        f"exposing {summary['open_ports_total']} open port(s)."
    ]
    issues = summary["findings_total"] + summary["vulnerabilities_total"]
    if issues:
        sev = summary["issues_by_severity"]
        listed = ", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev.get(s))
        parts.append(
            f"{issues} issue(s) were recorded ({listed}). Overall risk is rated "
            f"{summary['overall_risk'].upper()}."
        )
        if summary["kev_total"]:
            parts.append(
                f"{summary['kev_total']} vulnerability(ies) are listed in the CISA Known Exploited "
                "Vulnerabilities catalog and should be remediated first."
            )
    else:
        parts.append("No security issues were recorded by the operations included in this report.")
    if summary["operations_failed"]:
        parts.append(
            f"{summary['operations_failed']} operation(s) failed or were blocked; their results are "
            "not part of this report."
        )
    return " ".join(parts)


def build_report(
    db: Database, scope: Scope, settings: Settings, op_ids: list[int] | None = None
) -> dict[str, Any]:
    """Build the report document for all data, or only for *op_ids*."""
    if op_ids is None:
        operations = list(reversed(db.list_operations(limit=100000)))
        hosts = db.list_hosts()
    else:
        operations = [op for op in (db.get_operation(i) for i in op_ids) if op]
        seen: dict[str, Any] = {}
        for op_id in op_ids:
            for host in db.list_hosts(op_id):
                seen[host.address] = host
        hosts = list(seen.values())
    findings = db.list_findings(op_ids)
    vulns = db.list_rows("vulnerabilities", op_ids, "priority DESC, id")
    osint = db.list_rows("osint_records", op_ids, "kind, name, value")
    wifi = db.list_rows("wifi_networks", op_ids, "owned DESC, ssid")

    tools = sorted({op["command"].split()[0] for op in operations if op.get("command")})
    issue_counts: Counter[str] = Counter(f["severity"] for f in findings)
    issue_counts.update(v["severity"] for v in vulns)
    summary: dict[str, Any] = {
        "operations_total": len(operations),
        "operations_failed": sum(1 for op in operations if op["status"] != "completed"),
        "hosts_total": len(hosts),
        "open_ports_total": sum(len(h.ports) for h in hosts),
        "by_device_type": dict(Counter(h.device_type or "unknown" for h in hosts)),
        "by_subnet": {net: len(addrs) for net, addrs in subnet_map(hosts).items()},
        "findings_total": len(findings),
        "vulnerabilities_total": len(vulns),
        "kev_total": sum(1 for v in vulns if v["kev"]),
        "issues_by_severity": {s: issue_counts[s] for s in (*SEVERITIES, "unknown") if issue_counts[s]},
        "overall_risk": _overall_risk(issue_counts),
    }

    recommendations: list[dict[str, str]] = []
    seen_recs: set[str] = set()
    ranked = sorted(
        [(f["severity"], f["recommendation"], f["title"]) for f in findings]
        + [(v["severity"], v["recommendation"], f"{v['cve_id']} in {v['product']} {v['version']}".strip())
           for v in vulns],
        key=lambda item: -_RISK_WEIGHT.get(item[0], 0),
    )
    for severity, text, source in ranked:
        if text and text not in seen_recs:
            seen_recs.add(text)
            recommendations.append({"severity": severity, "recommendation": text, "source": source})

    return {
        "title": "KSIF Security Assessment Report",
        "generated_at": utc_now(),
        "operator": settings.operator,
        "engagement": scope.engagement,
        "mode": settings.mode.value,
        "scope": {
            "ips": scope.ips, "subnets": scope.subnets, "domains": scope.domains,
            "interfaces": scope.interfaces, "bssids": scope.bssids,
        },
        "tools": tools,
        "summary": summary,
        "executive_summary": _executive_summary(summary, scope.engagement),
        "operations": operations,
        "hosts": [asdict(h) for h in hosts],
        "findings": findings,
        "vulnerabilities": vulns,
        "osint": osint,
        "wifi": wifi,
        "recommendations": recommendations,
    }

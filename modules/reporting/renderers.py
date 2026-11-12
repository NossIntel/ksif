"""Report renderers: JSON, Markdown, HTML, CSV and (optional) PDF."""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.config import Settings
from core.database import Database

FORMATS = ("json", "markdown", "html", "csv", "pdf")


class ReportFormatUnavailable(RuntimeError):
    """The requested format needs an optional dependency that is missing."""


# ---------------------------------------------------------------- tables
def _tables(report: dict[str, Any]) -> list[tuple[str, list[str], list[list[Any]]]]:
    """Every report section as (title, header, rows). Empty sections are skipped."""
    scope = report["scope"]
    sections: list[tuple[str, list[str], list[list[Any]]]] = []
    scope_rows = [[kind, ", ".join(values)] for kind, values in scope.items() if values]
    if scope_rows:
        sections.append(("Authorized Scope", ["Type", "Targets"], scope_rows))
    if report["operations"]:
        sections.append((
            "Operations", ["#", "Started (UTC)", "Module", "Action", "Target", "Status", "Result"],
            [[op["id"], op["started_at"], op["module"], op["action"], op["target"], op["status"],
              op.get("summary") or op.get("error") or ""] for op in report["operations"]],
        ))
    if report["hosts"]:
        sections.append((
            "Hosts", ["Address", "Hostname", "MAC", "Vendor", "Device type", "OS guess", "Open ports"],
            [[h["address"], h["hostname"] or "", h["mac"] or "", h["vendor"] or "", h["device_type"] or "",
              f"{h['os_guess']} ({h['os_accuracy']}%)" if h["os_guess"] else "", len(h["ports"])]
             for h in report["hosts"]],
        ))
        port_rows = [
            [h["address"], f"{p['number']}/{p['protocol']}", p["state"], p["service"] or "",
             p["product"] or "", p["version"] or ""]
            for h in report["hosts"] for p in h["ports"]
        ]
        if port_rows:
            sections.append(("Ports and Services", ["Host", "Port", "State", "Service", "Product", "Version"],
                             port_rows))
    if report["vulnerabilities"]:
        sections.append((
            "Vulnerabilities", ["CVE", "Severity", "CVSS", "EPSS", "KEV", "Host", "Product", "Summary"],
            [[v["cve_id"], v["severity"], v["cvss"] if v["cvss"] is not None else "",
              f"{v['epss']:.3f}" if v["epss"] is not None else "", "yes" if v["kev"] else "",
              f"{v['host']}:{v['port']}" if v["port"] else v["host"],
              f"{v['product']} {v['version']}".strip(), v["summary"][:300]]
             for v in report["vulnerabilities"]],
        ))
    if report["findings"]:
        sections.append((
            "Findings", ["Severity", "Module", "Title", "Target", "Evidence"],
            [[f["severity"], f["module"], f["title"], f["target"], f["evidence"][:400]]
             for f in report["findings"]],
        ))
    if report["osint"]:
        sections.append(("OSINT Records", ["Kind", "Name", "Value", "Source"],
                         [[r["kind"], r["name"], r["value"][:300], r["source"]] for r in report["osint"]]))
    if report["wifi"]:
        sections.append((
            "Wi-Fi Networks", ["SSID", "BSSID", "Channel", "Band", "Security", "Signal", "Owned"],
            [[w["ssid"] or "<hidden>", w["bssid"], w["channel"] or "", w["band"], w["security"],
              w["signal"] if w["signal"] is not None else "", "yes" if w["owned"] else ""]
             for w in report["wifi"]],
        ))
    if report["recommendations"]:
        sections.append(("Recommendations", ["Priority", "Recommendation", "Related to"],
                         [[r["severity"], r["recommendation"], r["source"]] for r in report["recommendations"]]))
    return sections


def _meta(report: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        ("Generated (UTC)", report["generated_at"]),
        ("Operator", report["operator"]),
        ("Engagement", report["engagement"] or "(not set)"),
        ("Mode", report["mode"]),
        ("Tools used", ", ".join(report["tools"]) or "(none)"),
        ("Overall risk", report["summary"]["overall_risk"].upper()),
    ]


# ---------------------------------------------------------------- renderers
def render_json(report: dict[str, Any]) -> str:
    """Machine-readable report."""
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def _md_cell(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    """Human-readable Markdown report."""
    lines = [f"# {report['title']}", ""]
    lines += [f"- **{key}:** {_md_cell(value)}" for key, value in _meta(report)]
    lines += ["", "## Executive Summary", "", report["executive_summary"], ""]
    for title, header, rows in _tables(report):
        lines += [f"## {title}", "", "| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
        lines += ["| " + " | ".join(_md_cell(cell) for cell in row) + " |" for row in rows]
        lines.append("")
    return "\n".join(lines)


_CSS = """
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,'Segoe UI',Roboto,sans-serif;margin:0;padding:32px;line-height:1.5}
h1{color:#58d68d;border-bottom:2px solid #238636;padding-bottom:8px}h2{color:#79c0ff;margin-top:32px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0}
th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#161b22;color:#8b949e}tr:nth-child(even) td{background:#11161d}
.meta td:first-child{color:#8b949e;width:180px}.summary{background:#161b22;border-left:4px solid #238636;padding:12px 16px}
.sev-critical{color:#ff6b6b;font-weight:700}.sev-high{color:#ffa94d;font-weight:700}.sev-medium{color:#ffd43b}
.sev-low{color:#74c0fc}.sev-info,.sev-unknown{color:#8b949e}
@media print{body{background:#fff;color:#000}th{background:#eee;color:#000}tr:nth-child(even) td{background:#fafafa}
h1,h2{color:#000}.summary{background:#f4f4f4}}
"""
_SEVERITY_WORDS = {"critical", "high", "medium", "low", "info", "unknown"}


def _html_cell(value: Any) -> str:
    text = html.escape(str(value))
    if str(value) in _SEVERITY_WORDS:
        return f'<td class="sev-{text}">{text}</td>'
    return f"<td>{text}</td>"


def render_html(report: dict[str, Any]) -> str:
    """Self-contained HTML report (no external resources, everything escaped)."""
    out = [
        "<!DOCTYPE html>", '<html lang="en"><head><meta charset="utf-8">',
        f"<title>{html.escape(report['title'])}</title>", f"<style>{_CSS}</style></head><body>",
        f"<h1>{html.escape(report['title'])}</h1>", '<table class="meta">',
    ]
    out += [f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>" for k, v in _meta(report)]
    out += ["</table>", "<h2>Executive Summary</h2>",
            f'<p class="summary">{html.escape(report["executive_summary"])}</p>']
    for title, header, rows in _tables(report):
        out.append(f"<h2>{html.escape(title)}</h2><table><tr>")
        out.append("".join(f"<th>{html.escape(col)}</th>" for col in header) + "</tr>")
        out += ["<tr>" + "".join(_html_cell(cell) for cell in row) + "</tr>" for row in rows]
        out.append("</table>")
    out.append("</body></html>")
    return "\n".join(out)


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection from tool-controlled text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def render_csv(report: dict[str, Any]) -> str:
    """All sections in one CSV; a ``section`` column tells them apart."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    for title, header, rows in _tables(report):
        writer.writerow(["section", *header])
        for row in rows:
            writer.writerow([title, *(_csv_safe(cell) for cell in row)])
        writer.writerow([])
    return buffer.getvalue()


def render_pdf(report: dict[str, Any]) -> bytes:
    """PDF via WeasyPrint (optional dependency)."""
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]
    except (ImportError, OSError) as exc:
        raise ReportFormatUnavailable(
            "PDF needs WeasyPrint: sudo apt install weasyprint  (or: pip install weasyprint)"
        ) from exc
    return HTML(string=render_html(report)).write_pdf()


def pdf_available() -> bool:
    """True when the PDF renderer can be used."""
    try:
        import weasyprint  # type: ignore[import-not-found]  # noqa: F401
    except (ImportError, OSError):
        return False
    return True


_EXT = {"json": "json", "markdown": "md", "html": "html", "csv": "csv", "pdf": "pdf"}


def save_report(db: Database, settings: Settings, report: dict[str, Any], fmt: str) -> Path:
    """Render *report* as *fmt*, write it under ``reports/`` and register it."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown report format {fmt!r}")
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = settings.reports_dir / f"ksif_{stamp}.{_EXT[fmt]}"
    counter = 1
    while path.exists():
        path = settings.reports_dir / f"ksif_{stamp}_{counter}.{_EXT[fmt]}"
        counter += 1
    if fmt == "pdf":
        path.write_bytes(render_pdf(report))
    else:
        renderer = {"json": render_json, "markdown": render_markdown, "html": render_html, "csv": render_csv}[fmt]
        path.write_text(renderer(report), encoding="utf-8")
    op_ids = [op["id"] for op in report["operations"]]
    db.add_report(op_ids[0] if len(op_ids) == 1 else None, fmt, str(path))
    return path

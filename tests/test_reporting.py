import csv
import io
import json

import pytest

from core.models import Finding, Host, Port
from modules.reporting.builder import build_report
from modules.reporting.renderers import (
    ReportFormatUnavailable,
    pdf_available,
    render_csv,
    render_html,
    render_json,
    render_markdown,
    render_pdf,
    save_report,
)


@pytest.fixture
def populated(db):
    op = db.create_operation("network_discovery", "net.service_os", "192.168.1.0/24", "tester", "active",
                             "nmap -sV 192.168.1.0/24")
    db.save_hosts(op, [
        Host("192.168.1.1", "ipv4", mac="A4:91:B1:11:22:33", vendor="Technicolor", hostname="gw",
             os_guess="Linux 5.x", os_accuracy=96, device_type="router",
             ports=[Port(22, "tcp", "open", "ssh", "Dropbear", "2022.83"),
                    Port(80, "tcp", "open", "http", "nginx | <script>alert(1)</script>", "1.18.0")]),
        Host("192.168.1.50", "ipv4", device_type="printer", ports=[Port(9100, "tcp", "open")]),
    ])
    db.save_findings(op, [
        Finding("web_security", "headers", "medium", "Missing Content-Security-Policy",
                "http://192.168.1.1/", evidence="=cmd|' /C calc'!A0", recommendation="Add a CSP header"),
        Finding("web_security", "tls", "high", "TLS 1.0 enabled", "192.168.1.1:443",
                recommendation="Disable TLS 1.0/1.1"),
    ])
    db.upsert_rows("vulnerabilities", [{
        "op_id": op, "cve_id": "CVE-2021-23017", "host": "192.168.1.1", "port": 80, "product": "nginx",
        "version": "1.18.0", "cvss": 7.7, "severity": "high", "epss": 0.412, "kev": 1,
        "summary": "Off-by-one in the nginx resolver", "recommendation": "Upgrade nginx to 1.20.1 or later",
        "priority": 9.1, "source": "nvd", "updated_at": "2026-11-12T10:00:00+00:00",
    }], ("cve_id", "host", "port", "product"))
    db.finish_operation(op, "completed", summary="2 host(s) up")
    blocked = db.create_operation("network_discovery", "net.port_scan", "8.8.8.8", "tester", "active")
    db.finish_operation(blocked, "blocked", "8.8.8.8 is not in the authorized scope")
    return op


def test_report_contents(db, scope, settings, populated):
    report = build_report(db, scope, settings)
    assert report["operator"] == "tester" and report["engagement"] == "Unit test lab"
    assert report["scope"]["subnets"] == scope.subnets
    assert report["tools"] == ["nmap"]
    summary = report["summary"]
    assert (summary["hosts_total"], summary["open_ports_total"]) == (2, 3)
    assert summary["by_device_type"] == {"router": 1, "printer": 1}
    assert summary["by_subnet"] == {"192.168.1.0/24": 2}
    assert summary["issues_by_severity"] == {"high": 2, "medium": 1}
    assert summary["overall_risk"] == "high" and summary["kev_total"] == 1
    assert summary["operations_failed"] == 1
    assert "CISA Known Exploited" in report["executive_summary"]
    assert [r["severity"] for r in report["recommendations"]] == ["high", "high", "medium"]
    assert [f["severity"] for f in report["findings"]] == ["high", "medium"]


def test_report_limited_to_operation(db, scope, settings, populated):
    other = db.create_operation("network_discovery", "net.host_discovery", "10.0.0.5", "tester", "active")
    db.save_hosts(other, [Host("10.0.0.5", "ipv4")])
    db.finish_operation(other, "completed")
    report = build_report(db, scope, settings, [other])
    assert [h["address"] for h in report["hosts"]] == ["10.0.0.5"]
    assert report["findings"] == [] and report["vulnerabilities"] == []
    assert report["summary"]["overall_risk"] == "informational"


def test_json_roundtrip(db, scope, settings, populated):
    report = build_report(db, scope, settings)
    assert json.loads(render_json(report))["summary"]["hosts_total"] == 2


def test_markdown_sections_and_escaping(db, scope, settings, populated):
    text = render_markdown(build_report(db, scope, settings))
    for heading in ("## Executive Summary", "## Authorized Scope", "## Operations", "## Hosts",
                    "## Ports and Services", "## Vulnerabilities", "## Findings", "## Recommendations"):
        assert heading in text
    assert "nginx \\| <script>" in text
    for line in text.splitlines():
        if line.startswith("| 192.168.1.1 | 80/tcp"):
            assert line.count(" | ") == 5  # the pipe inside the banner did not add a column


def test_html_is_escaped_and_self_contained(db, scope, settings, populated):
    page = render_html(build_report(db, scope, settings))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert 'class="sev-high"' in page
    assert "http://" not in page.split("<body>")[0] and "<link" not in page and "src=" not in page


def test_csv_neutralises_formulas(db, scope, settings, populated):
    rows = list(csv.reader(io.StringIO(render_csv(build_report(db, scope, settings)))))
    evidence = [r for r in rows if r and r[0] == "Findings" and "Content-Security" in r[3]][0][5]
    assert evidence.startswith("'=")
    assert ["section", "Address", "Hostname", "MAC", "Vendor", "Device type", "OS guess", "Open ports"] in rows


def test_empty_database_report(db, scope, settings):
    report = build_report(db, scope, settings)
    text = render_markdown(report)
    assert "No security issues were recorded" in text
    assert "## Hosts" not in text and "## Findings" not in text
    assert render_html(report) and render_csv(report)


@pytest.mark.parametrize("fmt,ext", [("json", ".json"), ("markdown", ".md"), ("html", ".html"), ("csv", ".csv")])
def test_save_report_registers_in_db(db, scope, settings, populated, fmt, ext):
    report = build_report(db, scope, settings)
    first = save_report(db, settings, report, fmt)
    second = save_report(db, settings, report, fmt)
    assert first.suffix == ext and first.exists() and first != second
    rows = db.query("SELECT format, path FROM reports ORDER BY id")
    assert [r["format"] for r in rows] == [fmt, fmt] and rows[0]["path"] == str(first)


def test_unknown_format_rejected(db, scope, settings):
    with pytest.raises(ValueError):
        save_report(db, settings, build_report(db, scope, settings), "exe")


def test_pdf_either_works_or_says_why(db, scope, settings, populated):
    report = build_report(db, scope, settings)
    if pdf_available():
        assert render_pdf(report)[:4] == b"%PDF"
    else:
        with pytest.raises(ReportFormatUnavailable) as exc:
            render_pdf(report)
        assert "weasyprint" in str(exc.value).lower()

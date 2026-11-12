import pytest

from core.http import HttpResponse
from core.models import Mode
from integrations.base import ParseError
from integrations.web_tools import (
    NiktoIntegration,
    NucleiIntegration,
    WhatWebIntegration,
    WpscanIntegration,
)
from modules.web_security import actions
from modules.web_security.headers import analyze_headers
from tests.conftest import FakeHttp, FakeToolRunner, fixture_text


@pytest.fixture
def runner(audit, fake_dir):
    return FakeToolRunner(audit, fake_dir)


def yes(_p):
    return True


def url(raw="http://example.com/"):
    from core.validator import parse_target
    return parse_target(raw)


# ---------------------------------------------------------------- headers
def test_analyze_headers_flags_missing():
    findings = analyze_headers("https://example.com/", 200,
                               {"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4",
                                "set-cookie": "id=1; Path=/"}, is_https=True)
    titles = {f.title for f in findings}
    assert any("HSTS" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("Server version" in t for t in titles)
    assert any("X-Powered-By" in t for t in titles)
    assert any("HttpOnly" in t for t in titles)
    assert any("Secure" in t for t in titles)


def test_analyze_headers_clean_site():
    findings = analyze_headers("https://example.com/", 200, {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }, is_https=True)
    assert findings == []


# ---------------------------------------------------------------- integrations
def test_whatweb_parse():
    tech = WhatWebIntegration(None).parse(fixture_text("whatweb.txt"))
    assert tech.get("HTTPServer") == "nginx/1.18.0"
    assert tech.get("X-Powered-By") == "PHP/7.4.3"
    assert "JQuery" in tech


def test_nikto_parse():
    items = NiktoIntegration(None).parse(fixture_text("nikto.txt"))
    messages = [i["message"] for i in items]
    assert any("X-Frame-Options" in m for m in messages)
    assert any("Apache default file" in m for m in messages)
    assert not any("host(s) tested" in m for m in messages)
    assert not any(m.startswith("Server:") for m in messages)
    assert NiktoIntegration(None).parse_version("- Nikto v2.5.0") == "2.5.0"


def test_nuclei_parse():
    matches = NucleiIntegration(None).parse(fixture_text("nuclei.jsonl"))
    assert len(matches) == 3  # the non-json line is skipped
    high = next(m for m in matches if m["severity"] == "high")
    assert high["cves"] == ["CVE-2021-1234"]


def test_nuclei_parse_malformed_raises():
    with pytest.raises(ParseError):
        NucleiIntegration(None).parse('{"template-id": "x", broken}')


def test_nuclei_args_sanitised():
    args = NucleiIntegration(None).scan_args(url(), "high; rm -rf")
    assert args[args.index("-severity") + 1] == "high"


def test_wpscan_parse():
    data = WpscanIntegration(None).parse(fixture_text("wpscan.json"))
    assert data["version"] == "5.8.1"
    assert data["core_vulnerabilities"][0]["references"]["cve"] == ["2022-21664"]
    assert data["plugins"][0]["name"] == "contact-form-7"


# ---------------------------------------------------------------- actions
@pytest.fixture
def web_engine(make_engine):
    def build(**kw):
        engine = make_engine(**kw)
        actions.register(engine)
        return engine
    return build


def test_all_web_actions_registered(web_engine):
    ids = {a.id for a in web_engine().actions("web_security")}
    assert ids == {"web.fingerprint", "web.headers", "web.nikto", "web.nuclei", "web.wpscan"}


async def test_fingerprint_stores_tech(web_engine, db, fake_dir):
    (fake_dir / "whatweb.out").write_text(fixture_text("whatweb.txt"), encoding="utf-8")
    result = await web_engine().execute("web.fingerprint", "example.com", confirm=yes)
    assert result.status == "completed", result.error
    tech = {r["name"] for r in db.list_rows("osint_records") if r["kind"] == "technology"}
    assert "HTTPServer" in tech


async def test_headers_action_uses_http(web_engine, db):
    resp = HttpResponse("https://example.com/", 200,
                        {"server": "Apache/2.4.41"}, "", "https://example.com/")
    engine = web_engine(http=FakeHttp({"https://example.com/": resp}))
    result = await engine.execute("web.headers", "example.com", confirm=yes)
    assert result.status == "completed", result.error
    findings = db.list_findings([result.op_id])
    assert any("HSTS" in f["title"] for f in findings)


async def test_nuclei_creates_vulnerabilities(web_engine, db, fake_dir):
    (fake_dir / "nuclei.out").write_text(fixture_text("nuclei.jsonl"), encoding="utf-8")
    result = await web_engine().execute("web.nuclei", "http://example.com/", confirm=yes)
    assert result.status == "completed", result.error
    vulns = db.list_rows("vulnerabilities")
    assert any(v["cve_id"] == "CVE-2021-1234" for v in vulns)


async def test_wpscan_requires_owned_site(web_engine, db, fake_dir):
    (fake_dir / "wpscan.out").write_text(fixture_text("wpscan.json"), encoding="utf-8")
    engine = web_engine()
    # blog.lab.test is in scope.wordpress_sites (conftest); example.com is not
    denied = await engine.execute("web.wpscan", "http://example.com/", confirm=yes)
    assert denied.status == "failed" and "owner-only" in denied.error
    ok = await engine.execute("web.wpscan", "http://blog.lab.test/", confirm=yes)
    assert ok.status == "completed", ok.error
    assert any(v["cve_id"] == "CVE-2020-35489" for v in db.list_rows("vulnerabilities"))


async def test_web_actions_blocked_in_passive_mode(web_engine):
    engine = web_engine(mode=Mode.PASSIVE)
    result = await engine.execute("web.fingerprint", "example.com", confirm=yes)
    assert result.status == "blocked" and "passive mode" in result.error


async def test_web_action_out_of_scope_blocked(web_engine):
    result = await web_engine().execute("web.headers", "https://evil.com/", confirm=yes)
    assert result.status == "blocked"

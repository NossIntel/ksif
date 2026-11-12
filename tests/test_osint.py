import pytest

from core.http import TlsInfo
from core.models import TargetKind
from core.validator import ValidationError, parse_target
from integrations.osint_tools import (
    AmassIntegration,
    DigIntegration,
    SubfinderIntegration,
    TheHarvesterIntegration,
    WhoisIntegration,
)
from modules.osint import actions
from tests.conftest import FakeHttp, FakeToolRunner, events, fixture_text


@pytest.fixture
def runner(audit, fake_dir):
    return FakeToolRunner(audit, fake_dir)


def yes(_p):
    return True


def dom(raw="example.com"):
    return parse_target(raw)


# ---------------------------------------------------------------- integrations
def test_whois_args_and_parse(runner):
    tool = WhoisIntegration(runner)
    assert tool.query_args(dom()) == ["example.com"]
    fields = tool.parse(fixture_text("whois.txt"))
    assert fields["registrar"] == "Example Registrar, LLC"
    assert fields["expires"] == "2026-11-20T04:00:00Z"
    assert fields["nameservers"] == ["ns1.example.com", "ns2.example.com"]
    with pytest.raises(ValidationError):
        tool.query_args(parse_target("192.168.1.1"))


def test_dig_args_and_parse(runner):
    tool = DigIntegration(runner)
    args = tool.query_args(dom())
    assert args[0] == "+noall" and args[3] == "example.com" and "MX" in args
    records = tool.parse(fixture_text("dig.txt"))
    assert records["A"] == ["93.184.216.34"]
    assert records["MX"] == ["10 mail.example.com."]
    assert records["TXT"][0].startswith('"v=spf1')


def test_subfinder_parse_filters_domain(runner):
    found = SubfinderIntegration(runner).parse(fixture_text("subfinder.txt"), "example.com")
    assert "www.example.com" in found and "vpn.example.com" in found
    assert "not-the-domain.org" not in found
    assert found == sorted(set(found))  # deduplicated and sorted


def test_amass_args(runner):
    assert AmassIntegration(runner).query_args(dom()) == ["enum", "-passive", "-silent", "-d", "example.com"]


def test_theharvester_parse(runner):
    tool = TheHarvesterIntegration(runner)
    data = tool.parse(fixture_text("theharvester.txt"), "example.com")
    assert data["emails"] == ["admin@example.com", "sales@example.com"]  # other.org excluded
    assert "www.example.com" in data["hosts"] and "intranet.example.com" in data["hosts"]
    assert tool.parse_version("* theHarvester 4.5.1 *") == "4.5.1"
    assert "duckduckgo" in "".join(tool.query_args(dom()))


# ---------------------------------------------------------------- actions
@pytest.fixture
def osint_engine(make_engine):
    def build(**kw):
        engine = make_engine(**kw)
        actions.register(engine)
        return engine
    return build


def test_all_osint_actions_registered(osint_engine):
    ids = {a.id for a in osint_engine().actions("osint")}
    assert ids == {"osint.whois", "osint.dns", "osint.subdomains", "osint.tls_cert",
                   "osint.harvester", "osint.correlate"}
    assert all(a.intrusiveness.name == "PASSIVE" for a in osint_engine().actions("osint"))


async def test_whois_stores_records(osint_engine, db, fake_dir):
    (fake_dir / "whois.out").write_text(fixture_text("whois.txt"), encoding="utf-8")
    result = await osint_engine().execute("osint.whois", "example.com", confirm=yes)
    assert result.status == "completed", result.error
    rows = db.list_rows("osint_records", None, "name")
    names = {r["name"] for r in rows}
    assert "registrar" in names and "nameservers" in names


async def test_dns_flags_weak_spf(osint_engine, db, fake_dir):
    (fake_dir / "dig.out").write_text(fixture_text("dig.txt"), encoding="utf-8")
    result = await osint_engine().execute("osint.dns", "example.com", confirm=yes)
    assert result.status == "completed", result.error
    findings = db.list_findings([result.op_id])
    assert any("SPF" in f["title"] for f in findings)
    assert any(r["name"] == "A" for r in db.list_rows("osint_records"))


async def test_subdomains_uses_available_tool(osint_engine, db, fake_dir):
    (fake_dir / "subfinder.out").write_text(fixture_text("subfinder.txt"), encoding="utf-8")
    engine = osint_engine(available={"subfinder"})
    result = await engine.execute("osint.subdomains", "example.com", confirm=yes)
    assert result.status == "completed", result.error
    subs = {r["value"] for r in db.list_rows("osint_records") if r["kind"] == "subdomain"}
    assert "vpn.example.com" in subs


async def test_subdomains_blocked_when_no_tool(osint_engine):
    engine = osint_engine(available=set())
    result = await engine.execute("osint.subdomains", "example.com", confirm=yes)
    assert result.status == "blocked" and "missing tools" in result.error


async def test_tls_cert_flags_weak_protocol(osint_engine, db):
    tls = TlsInfo(host="example.com", port=443, protocol="TLSv1", cipher="AES128-SHA",
                  issuer="CN=Old CA", not_after="Jan  1 00:00:00 2020 GMT")
    engine = osint_engine(http=FakeHttp(tls=tls))
    result = await engine.execute("osint.tls_cert", "example.com", confirm=yes)
    assert result.status == "completed", result.error
    findings = db.list_findings([result.op_id])
    titles = {f["title"] for f in findings}
    assert any("Weak TLS" in t for t in titles) and any("expired" in t for t in titles)


async def test_tls_cert_out_of_scope_blocked(osint_engine):
    result = await osint_engine().execute("osint.tls_cert", "evil.com", confirm=yes)
    assert result.status == "blocked"


async def test_harvester_stores_emails(osint_engine, db, fake_dir):
    (fake_dir / "theHarvester.out").write_text(fixture_text("theharvester.txt"), encoding="utf-8")
    result = await osint_engine().execute("osint.harvester", "example.com", confirm=yes)
    assert result.status == "completed", result.error
    emails = {r["value"] for r in db.list_rows("osint_records") if r["kind"] == "email"}
    assert emails == {"admin@example.com", "sales@example.com"}


async def test_correlate_reads_stored_osint(osint_engine, db, fake_dir):
    (fake_dir / "whois.out").write_text(fixture_text("whois.txt"), encoding="utf-8")
    engine = osint_engine()
    await engine.execute("osint.whois", "example.com", confirm=yes)
    result = await engine.execute("osint.correlate", "", confirm=yes)
    assert result.status == "completed", result.error
    assert result.output.data["by_kind"].get("whois")


async def test_passive_actions_run_in_passive_mode(osint_engine, fake_dir):
    (fake_dir / "whois.out").write_text(fixture_text("whois.txt"), encoding="utf-8")
    from core.models import Mode
    engine = osint_engine(mode=Mode.PASSIVE)

    def never(_p):
        raise AssertionError("passive action must not prompt")

    result = await engine.execute("osint.whois", "example.com", confirm=never)
    assert result.status == "completed", result.error

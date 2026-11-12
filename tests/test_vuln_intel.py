import pytest

from core.models import Host, Port
from integrations import vuln_intel as vi
from modules.vulnerability_intelligence import actions
from tests.conftest import FakeIntel

NVD_SAMPLE = {
    "vulnerabilities": [
        {"cve": {"id": "CVE-2021-23017",
                 "descriptions": [{"lang": "en", "value": "nginx resolver off-by-one"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.7, "baseSeverity": "HIGH"}}]}}},
        {"cve": {"id": "CVE-2019-20372",
                 "descriptions": [{"lang": "en", "value": "nginx error_page request smuggling"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}]}}},
    ]
}
EPSS_SAMPLE = {"data": [{"cve": "CVE-2021-23017", "epss": "0.412"}, {"cve": "CVE-2019-20372", "epss": "0.05"}]}
KEV_SAMPLE = {"vulnerabilities": [{"cveID": "CVE-2021-23017"}, {"cveID": "CVE-2017-0144"}]}


def yes(_p):
    return True


# ---------------------------------------------------------------- parsing
def test_nvd_url_and_parse():
    url = vi.nvd_search_url("nginx 1.18.0; rm", results=500)
    assert "keywordSearch=nginx%201.18.0%20%20rm" in url and "resultsPerPage=100" in url
    records = vi.parse_nvd(NVD_SAMPLE)
    assert records[0]["cve_id"] == "CVE-2021-23017" and records[0]["cvss"] == 7.7
    assert records[0]["severity"] == "high"
    assert vi.parse_nvd(None) == []


def test_epss_and_kev_parse():
    assert vi.parse_epss(EPSS_SAMPLE)["CVE-2021-23017"] == 0.412
    assert vi.parse_kev(KEV_SAMPLE) == {"CVE-2021-23017", "CVE-2017-0144"}
    assert vi.parse_epss(None) == {} and vi.parse_kev(None) == set()


def test_priority():
    assert vi.priority(7.7, 0.4, False) < vi.priority(7.7, 0.4, True)  # KEV dominates
    assert vi.priority(None, None, False) > 0
    assert vi.priority(9.8, 0.9, True) <= 11.0


def test_severity_from_score():
    assert vi.severity_from_score(9.5) == "critical"
    assert vi.severity_from_score(5.0) == "medium"
    assert vi.severity_from_score(None) == "unknown"


# ---------------------------------------------------------------- actions
@pytest.fixture
def intel():
    return FakeIntel({"services.nvd.nist.gov": NVD_SAMPLE, "api.first.org": EPSS_SAMPLE, "cisa.gov": KEV_SAMPLE})


@pytest.fixture
def vuln_engine(make_engine, intel):
    def build(**kw):
        engine = make_engine(intel=kw.pop("intel", intel), **kw)
        actions.register(engine)
        return engine
    return build


def test_all_vuln_actions_registered(vuln_engine):
    ids = {a.id for a in vuln_engine().actions("vulnerability_intelligence")}
    assert ids == {"vuln.enrich", "vuln.lookup", "vuln.kev", "vuln.prioritize"}


async def test_enrich_correlates_services(vuln_engine, db):
    op = db.create_operation("network_discovery", "net.service_os", "t", "o", "active")
    db.save_hosts(op, [Host("192.168.1.1", "ipv4",
                            ports=[Port(80, "tcp", "open", "http", "nginx", "1.18.0")])])
    db.finish_operation(op, "completed")
    result = await vuln_engine().execute("vuln.enrich", "", confirm=yes)
    assert result.status == "completed", result.error
    vulns = db.list_rows("vulnerabilities", None, "priority DESC")
    assert vulns[0]["cve_id"] == "CVE-2021-23017"
    assert vulns[0]["kev"] == 1 and vulns[0]["epss"] == 0.412
    assert vulns[0]["priority"] > vulns[1]["priority"]
    findings = db.list_findings([result.op_id])
    assert any("CISA KEV" in f["title"] for f in findings)


async def test_enrich_without_services(vuln_engine):
    result = await vuln_engine().execute("vuln.enrich", "", confirm=yes)
    assert result.status == "completed" and "no versioned services" in result.output.summary


async def test_lookup_query(vuln_engine, db):
    result = await vuln_engine().execute("vuln.lookup", "", {"query": "nginx 1.18.0"}, confirm=yes)
    assert result.status == "completed", result.error
    assert len(db.list_rows("vulnerabilities")) == 2


async def test_consent_required(vuln_engine):
    result = await vuln_engine().execute("vuln.lookup", "", {"query": "nginx"}, confirm=lambda _p: False)
    assert result.status == "blocked" and "consent" in result.error.lower()


async def test_kev_refresh_flags_stored(vuln_engine, db):
    op = db.create_operation("m", "a", "t", "o", "passive")
    db.save_vulnerabilities(op, [
        {"cve_id": "CVE-2021-23017", "host": "h", "product": "nginx", "cvss": 7.7, "severity": "high",
         "kev": False, "priority": 5.0, "source": "nvd"},
        {"cve_id": "CVE-2000-0000", "host": "h", "product": "x", "cvss": 3.0, "severity": "low",
         "kev": False, "priority": 2.0, "source": "nvd"}])
    result = await vuln_engine().execute("vuln.kev", "", confirm=yes)
    assert result.status == "completed", result.error
    assert result.output.data["flagged"] == 1
    rows = {r["cve_id"]: r for r in db.list_rows("vulnerabilities")}
    assert rows["CVE-2021-23017"]["kev"] == 1


async def test_prioritize_is_offline(make_engine, db):
    # no intel client needed; FakeIntel that raises would prove offline, but None is enough
    engine = make_engine()
    actions.register(engine)
    op = db.create_operation("m", "a", "t", "o", "passive")
    db.save_vulnerabilities(op, [{"cve_id": "CVE-1", "host": "h", "product": "p", "cvss": 9.0,
                                  "severity": "critical", "kev": True, "priority": 10.0, "source": "nvd"}])
    result = await engine.execute("vuln.prioritize", "", confirm=yes)
    assert result.status == "completed", result.error
    assert result.output.data["by_severity"]["critical"] == 1 and result.output.data["kev"] == 1

import pytest

from core.models import Mode
from integrations.wifi_tools import (
    IwIntegration,
    NmcliIntegration,
    band_of,
    normalize_security,
    weakest,
)
from modules.wifi_audit import actions
from tests.conftest import FakeToolRunner, fixture_text


@pytest.fixture
def runner(audit, fake_dir):
    return FakeToolRunner(audit, fake_dir)


def never(_p):
    raise AssertionError("passive action must not prompt")


# ---------------------------------------------------------------- helpers
@pytest.mark.parametrize("freq,band", [(2437, "2.4GHz"), (5180, "5GHz"), (6200, "6GHz"), (100, "")])
def test_band_of(freq, band):
    assert band_of(freq) == band


@pytest.mark.parametrize("raw,norm,weak", [
    ("", "OPEN", "open"), ("WEP", "WEP", "wep"), ("WPA1", "WPA1", "wpa1"),
    ("WPA2", "WPA2", "wpa2"), ("WPA1 WPA2", "WPA2 WPA1", "wpa2"), ("WPA3", "WPA3", "wpa3"),
])
def test_security_normalisation(raw, norm, weak):
    assert normalize_security(raw) == norm
    assert weakest(norm) == weak


# ---------------------------------------------------------------- parsing
def test_nmcli_parse():
    nets = NmcliIntegration(None).parse(fixture_text("nmcli_wifi.txt"))
    by_bssid = {n["bssid"]: n for n in nets}
    assert by_bssid["aa:bb:cc:dd:ee:ff"]["security"] == "WEP"
    assert by_bssid["aa:bb:cc:dd:ee:ff"]["channel"] == 6
    assert by_bssid["aa:bb:cc:dd:ee:ff"]["band"] == "2.4GHz"
    assert by_bssid["22:33:44:55:66:77"]["security"] == "OPEN"
    assert by_bssid["44:55:66:77:88:99"]["band"] == "5GHz"
    # NeighborAP appears twice; deduplicated by BSSID
    assert len(nets) == 5


def test_iw_parse():
    nets = IwIntegration(None).parse(fixture_text("iw_scan.txt"))
    assert nets[0]["bssid"] == "aa:bb:cc:dd:ee:ff" and nets[0]["security"] == "WPA2"
    assert nets[0]["ssid"] == "HomeNet" and nets[0]["channel"] == 6
    assert nets[1]["security"] == "WEP"  # Privacy bit, no RSN/WPA


# ---------------------------------------------------------------- actions
@pytest.fixture
def wifi_engine(make_engine):
    def build(**kw):
        engine = make_engine(**kw)
        actions.register(engine)
        return engine
    return build


def test_all_wifi_actions_passive(wifi_engine):
    acts = wifi_engine().actions("wifi_audit")
    assert {a.id for a in acts} == {"wifi.scan", "wifi.scan_iw", "wifi.audit"}
    assert all(a.intrusiveness.name == "PASSIVE" for a in acts)


async def test_scan_stores_networks_and_flags_owned_weak(wifi_engine, db, fake_dir):
    (fake_dir / "nmcli.out").write_text(fixture_text("nmcli_wifi.txt"), encoding="utf-8")
    engine = wifi_engine(mode=Mode.PASSIVE)
    result = await engine.execute("wifi.scan", "", confirm=never)
    assert result.status == "completed", result.error
    stored = db.list_rows("wifi_networks")
    owned = [n for n in stored if n["owned"]]
    assert len(owned) == 1 and owned[0]["bssid"] == "aa:bb:cc:dd:ee:ff"
    findings = db.list_findings([result.op_id])
    assert any("weak security" in f["title"] and f["severity"] == "high" for f in findings)
    # a neighbour's open network is stored but never raised as a finding
    assert not any("22:33:44:55:66:77" in f["target"] for f in findings)


async def test_scan_iw_needs_interface_in_scope(wifi_engine, db, fake_dir):
    (fake_dir / "iw.out").write_text(fixture_text("iw_scan.txt"), encoding="utf-8")
    engine = wifi_engine()
    ok = await engine.execute("wifi.scan_iw", "eth0", confirm=lambda _p: True)
    assert ok.status == "completed", ok.error
    blocked = await engine.execute("wifi.scan_iw", "tun0", confirm=lambda _p: True)
    assert blocked.status == "blocked"  # tun0 not in scope interfaces


async def test_audit_reads_stored(wifi_engine, db, fake_dir):
    (fake_dir / "nmcli.out").write_text(fixture_text("nmcli_wifi.txt"), encoding="utf-8")
    engine = wifi_engine(mode=Mode.PASSIVE)
    await engine.execute("wifi.scan", "", confirm=never)
    result = await engine.execute("wifi.audit", "", confirm=never)
    assert result.status == "completed", result.error
    assert result.output.data["by_security"]["WEP"] == 1
    assert any(f["severity"] == "high" for f in db.list_findings([result.op_id]))

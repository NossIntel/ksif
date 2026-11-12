import json

import pytest

from core.models import Host, Mode, Port
from modules.network_discovery import actions
from modules.network_discovery.device_classifier import classify_device
from modules.network_discovery.oui import OuiDatabase
from modules.network_discovery.topology import subnet_map, topology_edges
from tests.conftest import FIXTURES, events, fixture_text


def yes(_prompt):
    return True


@pytest.fixture(autouse=True)
def sample_oui(monkeypatch):
    monkeypatch.setattr(actions, "_oui", OuiDatabase([FIXTURES / "oui_sample.txt"]))


def h(ports=(), **kw):
    return Host("192.168.1.9", "ipv4", ports=[Port(p, "tcp", "open") for p in ports], **kw)


# ---------------------------------------------------------------- OUI
def test_oui_lookup_formats():
    oui = OuiDatabase([FIXTURES / "oui_sample.txt"])
    assert len(oui) == 3
    assert oui.lookup("B8:27:EB:44:55:66") == "Raspberry Pi Foundation"
    assert oui.lookup("b8-27-eb-44-55-66") == "Raspberry Pi Foundation"
    assert oui.lookup("b827.eb44.5566") == "Raspberry Pi Foundation"
    assert oui.lookup("00:00:00:00:00:00") is None
    assert oui.lookup("") is None and oui.lookup(None) is None and oui.lookup("zz") is None


def test_oui_no_database_file(tmp_path):
    oui = OuiDatabase([tmp_path / "missing.txt"])
    assert oui.lookup("B8:27:EB:44:55:66") is None and oui.source is None


def test_oui_ieee_format(tmp_path):
    path = tmp_path / "oui.txt"
    path.write_text("B8-27-EB   (hex)\t\tRaspberry Pi Foundation\nB827EB     (base 16)\t\tRaspberry Pi Foundation\n",
                    encoding="utf-8")
    assert OuiDatabase([path]).lookup("b8:27:eb:00:00:01") == "Raspberry Pi Foundation"


# ---------------------------------------------------------------- classifier
@pytest.mark.parametrize(
    "host,expected",
    [
        (h([80, 9100]), "printer"),
        (h([554]), "network-camera"),
        (h([445, 3389]), "windows-host"),
        (h([53, 80], vendor="TP-Link Technologies"), "router"),
        (h([2049]), "nas"),
        (h([1883]), "iot"),
        (h([], os_guess="Microsoft Windows 11"), "windows-host"),
        (h([], os_guess="OpenWrt 21.02 (Linux 5.4)"), "router"),
        (h([], os_guess="Android 13"), "mobile"),
        (h([], vendor="Brother industries"), "printer"),
        (h([], vendor="Hangzhou Hikvision"), "network-camera"),
        (h([], vendor="Raspberry Pi Foundation"), "iot"),
        (h([], vendor="Apple, Inc."), "mobile"),
        (h([80, 443, 3306]), "server"),
        (h([22]), "linux-host"),
        (h([]), "unknown"),
        (h([12345]), "unknown"),
    ],
)
def test_classify_device(host, expected):
    assert classify_device(host) == expected


# ---------------------------------------------------------------- topology
def test_subnet_map_groups_v4_and_v6():
    hosts = [Host("192.168.1.20", "ipv4"), Host("192.168.1.3", "ipv4"), Host("10.0.0.5", "ipv4"),
             Host("fd00::10", "ipv6")]
    assert subnet_map(hosts) == {
        "10.0.0.0/24": ["10.0.0.5"],
        "192.168.1.0/24": ["192.168.1.3", "192.168.1.20"],
        "fd00::/64": ["fd00::10"],
    }


def test_edges_deduplicated():
    hosts = [Host("192.168.1.1", "ipv4", hops=["192.168.1.1"]),
             Host("192.168.1.50", "ipv4", hops=["192.168.1.1", "192.168.1.50"]),
             Host("10.9.9.9", "ipv4", hops=["192.168.1.1", "10.0.0.1"]),
             Host("192.168.1.7", "ipv4")]
    assert topology_edges(hosts) == [
        ("scanner", "192.168.1.1"), ("192.168.1.1", "192.168.1.50"), ("192.168.1.1", "10.0.0.1"),
        ("10.0.0.1", "10.9.9.9"), ("scanner", "192.168.1.7"),
    ]


# ---------------------------------------------------------------- actions (full pipeline, fake tools)
@pytest.fixture
def engine(make_engine):
    engine = make_engine()
    actions.register(engine)
    return engine


def last_args(fake_dir, binary):
    return json.loads((fake_dir / f"{binary}.args").read_text().strip().splitlines()[-1])


def test_all_actions_registered(engine):
    ids = {a.id for a in engine.actions("network_discovery")}
    assert ids == {"net.host_discovery", "net.arp_scan", "net.port_scan", "net.service_os",
                   "net.topology", "net.fast_sweep", "net.passive_capture"}


async def test_host_discovery_end_to_end(engine, db, fake_dir):
    (fake_dir / "nmap.out").write_text(fixture_text("nmap_ping_sweep.xml"), encoding="utf-8")
    result = await engine.execute("net.host_discovery", "192.168.1.0/24", confirm=yes)
    assert result.status == "completed", result.error
    assert last_args(fake_dir, "nmap") == ["-sn", "-oX", "-", "192.168.1.0/24"]
    stored = {x.address: x for x in db.list_hosts(result.op_id)}
    assert stored["192.168.1.23"].vendor == "Raspberry Pi Foundation"  # from the OUI database
    assert stored["192.168.1.23"].device_type == "iot"
    assert result.output.data["subnets"] == {"192.168.1.0/24": ["192.168.1.1", "192.168.1.23"]}
    op = db.get_operation(result.op_id)
    assert op["command"].startswith("nmap -sn") and op["raw_output_path"].endswith(".xml")
    assert op["summary"] == "2 host(s) up, 0 open port(s)"


async def test_service_os_persists_ports_and_topology_edges(engine, db, fake_dir):
    (fake_dir / "nmap.out").write_text(fixture_text("nmap_full.xml"), encoding="utf-8")
    result = await engine.execute("net.service_os", "192.168.1.0/24", {"ports": "22,80"}, confirm=yes)
    assert result.status == "completed", result.error
    args = last_args(fake_dir, "nmap")
    assert "-sV" in args and "-O" in args and args[args.index("-p") + 1] == "22,80"
    stored = {x.address: x for x in db.list_hosts()}
    assert stored["192.168.1.1"].device_type == "router"
    assert stored["192.168.1.50"].device_type == "printer"
    assert stored["fd00::10"].device_type == "windows-host"
    assert [p.version for p in stored["192.168.1.1"].ports][:2] == ["2022.83", "2.89"]

    topo = await engine.execute("net.topology", "192.168.1.0/24", confirm=yes)
    assert ["192.168.1.1", "192.168.1.50"] in [list(e) for e in topo.output.data["edges"]]


async def test_bad_ports_param_fails_without_running(engine, fake_dir):
    result = await engine.execute("net.port_scan", "192.168.1.1", {"ports": "80 --script vuln"}, confirm=yes)
    assert result.status == "failed" and "ValidationError" in result.error
    assert not (fake_dir / "nmap.args").exists()


async def test_truncated_output_fails_and_keeps_raw_file(engine, db, fake_dir):
    (fake_dir / "nmap.out").write_text(fixture_text("nmap_truncated.xml"), encoding="utf-8")
    result = await engine.execute("net.port_scan", "192.168.1.0/24", confirm=yes)
    assert result.status == "failed" and "ParseError" in result.error
    assert db.list_hosts() == []
    op = db.get_operation(result.op_id)
    assert op["status"] == "failed"
    with open(op["raw_output_path"], encoding="utf-8") as handle:
        assert "<nmaprun" in handle.read()


async def test_arp_scan_requires_scoped_interface(engine, fake_dir):
    (fake_dir / "arp-scan.out").write_text(fixture_text("arp_scan.txt"), encoding="utf-8")
    good = await engine.execute("net.arp_scan", "192.168.1.0/24", {"interface": "eth0"}, confirm=yes)
    assert good.status == "completed" and len(good.output.hosts) == 3
    bad = await engine.execute("net.arp_scan", "192.168.1.0/24", {"interface": "tun9"}, confirm=yes)
    assert bad.status == "failed" and "not in the authorized scope" in bad.error


async def test_fast_sweep_caps_rate(engine, fake_dir):
    (fake_dir / "masscan.out").write_text(fixture_text("masscan.json"), encoding="utf-8")
    result = await engine.execute("net.fast_sweep", "192.168.1.0/24", {"rate": "90000"}, confirm=yes)
    assert result.status == "completed", result.error
    args = last_args(fake_dir, "masscan")
    assert args[args.index("--rate") + 1] == "1000"


async def test_passive_capture_runs_in_passive_mode(make_engine, fake_dir, db):
    engine = make_engine(mode=Mode.PASSIVE)
    actions.register(engine)
    (fake_dir / "tshark.out").write_text(fixture_text("tshark_fields.tsv"), encoding="utf-8")

    def never(_prompt):
        raise AssertionError("passive action must not ask for confirmation")

    result = await engine.execute("net.passive_capture", "eth0", {"duration": "5"}, confirm=never)
    assert result.status == "completed", result.error
    assert result.output.data["protocols"]["TCP"] == 2
    assert len(db.list_hosts()) == 3

    blocked = await engine.execute("net.passive_capture", "tun0", confirm=never)
    assert blocked.status == "blocked"


async def test_active_actions_blocked_in_passive_mode_and_out_of_scope(make_engine, fake_dir, db):
    engine = make_engine(mode=Mode.PASSIVE)
    actions.register(engine)
    for action in ("net.host_discovery", "net.port_scan", "net.fast_sweep"):
        assert (await engine.execute(action, "192.168.1.1", confirm=yes)).status == "blocked"
    engine.set_mode(Mode.ACTIVE)
    for target in ("8.8.8.8", "192.168.0.0/16", "scanme.nmap.org"):
        assert (await engine.execute("net.port_scan", target, confirm=yes)).status == "blocked"
    assert not list(fake_dir.glob("*.args"))  # no process was ever spawned
    assert "command_started" not in events(db)

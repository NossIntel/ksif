import pytest

from core.validator import ValidationError, parse_target
from integrations.arp_scan import ArpScanIntegration
from integrations.base import ParseError
from integrations.masscan import MasscanIntegration
from integrations.nmap import NmapIntegration
from integrations.tshark import TsharkIntegration
from tests.conftest import FakeToolRunner, fixture_text


@pytest.fixture
def runner(audit, fake_dir):
    return FakeToolRunner(audit, fake_dir)


# ---------------------------------------------------------------- nmap
def test_host_discovery_args(runner):
    nmap = NmapIntegration(runner)
    assert nmap.host_discovery_args(parse_target("192.168.1.0/24")) == ["-sn", "-oX", "-", "192.168.1.0/24"]


def test_ipv6_adds_flag(runner):
    nmap = NmapIntegration(runner)
    assert "-6" in nmap.host_discovery_args(parse_target("fd00::1"))
    assert "-6" in nmap.port_scan_args(parse_target("fd00::/64"))
    assert "-6" not in nmap.port_scan_args(parse_target("192.168.1.1"))


def test_port_scan_caps_rate_and_timing(runner):
    args = NmapIntegration(runner).port_scan_args(parse_target("192.168.1.1"), timing=5, max_rate=99999)
    assert "-T4" in args and "-T5" not in args
    assert args[args.index("--max-rate") + 1] == "1000"


def test_port_scan_validates_ports(runner):
    nmap = NmapIntegration(runner)
    with pytest.raises(ValidationError):
        nmap.port_scan_args(parse_target("192.168.1.1"), ports="22;id")
    with pytest.raises(ValidationError):
        nmap.port_scan_args(parse_target("192.168.1.1"), ports="--script=vuln")
    args = nmap.port_scan_args(parse_target("192.168.1.1"), ports="22, 80")
    assert args[args.index("-p") + 1] == "22,80" and "--top-ports" not in args


def test_target_is_last_arg_and_flags(runner):
    args = NmapIntegration(runner).port_scan_args(
        parse_target("192.168.1.1"), service_detection=True, os_detection=True, traceroute=True
    )
    assert args[-1] == "192.168.1.1"
    assert {"-sV", "-O", "--traceroute"} <= set(args)
    assert not any(a.startswith("--script") for a in args)


def test_nmap_rejects_url_target(runner):
    with pytest.raises(ValidationError):
        NmapIntegration(runner).host_discovery_args(parse_target("http://192.168.1.1/"))


def test_parse_full(runner):
    hosts = NmapIntegration(runner).parse_xml(fixture_text("nmap_full.xml"))
    assert [h.address for h in hosts] == ["192.168.1.1", "192.168.1.50", "fd00::10"]
    gw = hosts[0]
    assert gw.family == "ipv4" and gw.mac == "A4:91:B1:11:22:33"
    assert gw.vendor == "Technicolor Delivery Technologies Belgium NV"
    assert gw.hostname == "gateway.lan"
    assert [(p.number, p.service, p.product, p.version) for p in gw.ports] == [
        (22, "ssh", "Dropbear sshd", "2022.83"), (53, "domain", "dnsmasq", "2.89"),
        (80, "http", "nginx", "1.18.0"), (443, "http", "nginx", "1.18.0"),
    ]
    assert (gw.os_guess, gw.os_accuracy) == ("Linux 4.15 - 5.8", 96)
    assert gw.hops == ["192.168.1.1"]
    assert hosts[1].hops == ["192.168.1.1", "192.168.1.50"] and hosts[1].os_guess is None
    assert hosts[2].family == "ipv6" and hosts[2].mac is None and len(hosts[2].ports) == 2


def test_parse_ping_sweep(runner):
    hosts = NmapIntegration(runner).parse_xml(fixture_text("nmap_ping_sweep.xml"))
    assert [(h.address, h.vendor, h.hostname) for h in hosts] == [
        ("192.168.1.1", "Technicolor", None), ("192.168.1.23", None, "raspberrypi.lan"),
    ]
    assert all(h.ports == [] for h in hosts)


@pytest.mark.parametrize("xml", ["", "   ", "<html></html>", "not xml",
                                 '<nmaprun><host><status state="up"/></host></nmaprun>'])
def test_parse_bad_xml_raises(runner, xml):
    with pytest.raises(ParseError):
        NmapIntegration(runner).parse_xml(xml)


def test_parse_truncated_raises(runner):
    with pytest.raises(ParseError):
        NmapIntegration(runner).parse_xml(fixture_text("nmap_truncated.xml"))


def test_nmap_parse_version(runner):
    nmap = NmapIntegration(runner)
    assert nmap.parse_version("Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64") == "7.95"
    assert nmap.parse_version("command not found") is None


async def test_self_test_runs_the_tool(runner, fake_dir):
    (fake_dir / "nmap.out").write_text("Nmap version 7.95 ( https://nmap.org )\n", encoding="utf-8")
    nmap = NmapIntegration(runner)
    assert await nmap.self_test() == (True, "7.95")
    assert await nmap.version() == "7.95"
    assert (fake_dir / "nmap.args").read_text().strip() == '["--version"]\n["--version"]'.replace("\n", "\n")


async def test_self_test_unexpected_output_and_missing(audit, fake_dir):
    (fake_dir / "nmap.out").write_text("garbage\n", encoding="utf-8")
    ok, message = await NmapIntegration(FakeToolRunner(audit, fake_dir)).self_test()
    assert not ok and "unexpected output" in message
    ok, message = await NmapIntegration(FakeToolRunner(audit, fake_dir, available=set())).self_test()
    assert not ok and "not installed" in message and "apt install nmap" in message


# ---------------------------------------------------------------- arp-scan
def test_arp_scan_args_and_parse(runner):
    tool = ArpScanIntegration(runner)
    assert tool.scan_args("eth0", parse_target("192.168.1.0/24")) == [
        "--interface=eth0", "--retry=2", "192.168.1.0/24"]
    hosts = tool.parse(fixture_text("arp_scan.txt"))
    assert [(h.address, h.mac, h.vendor) for h in hosts] == [
        ("192.168.1.1", "a4:91:b1:11:22:33", "Technicolor Delivery Technologies Belgium NV"),
        ("192.168.1.23", "b8:27:eb:44:55:66", "Raspberry Pi Foundation"),
        ("192.168.1.77", "02:11:22:33:44:55", None),
    ]
    assert tool.parse("") == []
    assert tool.parse_version("arp-scan 1.10.0\n\nCopyright") == "1.10.0"


def test_arp_scan_rejects_ipv6_and_bad_interface(runner):
    tool = ArpScanIntegration(runner)
    with pytest.raises(ValidationError):
        tool.scan_args("eth0", parse_target("fd00::/64"))
    with pytest.raises(ValidationError):
        tool.scan_args("eth0 --file=/etc/shadow", parse_target("192.168.1.0/24"))


# ---------------------------------------------------------------- masscan
def test_masscan_args_cap_rate(runner):
    tool = MasscanIntegration(runner)
    args = tool.scan_args(parse_target("192.168.1.0/24"), "80,443", rate=5_000_000)
    assert args == ["-p", "80,443", "--rate", "1000", "-oJ", "-", "192.168.1.0/24"]
    with pytest.raises(ValidationError):
        tool.scan_args(parse_target("fd00::1"), "80")
    with pytest.raises(ValidationError):
        tool.scan_args(parse_target("192.168.1.1"), "80 --banners")


@pytest.mark.parametrize("name", ["masscan.json", "masscan_legacy.json"])
def test_masscan_parse(runner, name):
    hosts = MasscanIntegration(runner).parse(fixture_text(name))
    assert hosts[0].address == "192.168.1.1" and hosts[0].ports[0].number == 80
    assert hosts[1].address == "192.168.1.50"
    if name == "masscan.json":
        assert [p.number for p in hosts[0].ports] == [80, 443]


def test_masscan_parse_empty_and_malformed(runner):
    tool = MasscanIntegration(runner)
    assert tool.parse("") == [] and tool.parse("[]") == [] and tool.parse("[\n]\n") == []
    with pytest.raises(ParseError):
        tool.parse("FAIL: could not determine default interface")
    assert tool.parse_version("\nMasscan version 1.3.2 ( https://github.com/robertdavidgraham/masscan )") == "1.3.2"


# ---------------------------------------------------------------- tshark
def test_tshark_args_cap_duration(runner):
    tool = TsharkIntegration(runner)
    args = tool.capture_args("eth0", 99999)
    assert args[:4] == ["-i", "eth0", "-a", "duration:300"]
    assert "-w" not in args
    with pytest.raises(ValidationError):
        tool.capture_args("-r", 10)


def test_tshark_parse(runner):
    hosts, protocols = TsharkIntegration(runner).parse(fixture_text("tshark_fields.tsv"))
    assert [(h.address, h.family, h.mac) for h in hosts] == [
        ("192.168.1.1", "ipv4", "a4:91:b1:11:22:33"),
        ("192.168.1.23", "ipv4", "b8:27:eb:44:55:66"),
        ("fe80::21b:a9ff:feaa:bbcc", "ipv6", "00:1b:a9:aa:bb:cc"),
    ]
    assert protocols == {"DNS": 1, "TCP": 2, "TLSv1.3": 1, "ICMPv6": 1, "ARP": 1, "DHCP": 1}
    assert TsharkIntegration(runner).parse("") == ([], {})
    assert TsharkIntegration(runner).parse_version("TShark (Wireshark) 4.4.1.\n") == "4.4.1"

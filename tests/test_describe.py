"""Tests for Engine.describe: how-to text and exact-command preview."""

import pytest

from modules.network_discovery import actions as net
from modules.osint import actions as osint
from modules.password_lab import actions as pw
from modules.vulnerability_intelligence import actions as vuln
from modules.web_security import actions as web
from modules.wifi_audit import actions as wifi


@pytest.fixture
def full(make_engine):
    engine = make_engine()
    for module in (net, osint, web, wifi, pw, vuln):
        module.register(engine)
    return engine


def test_every_action_has_usage_and_a_command(full):
    for action in full.actions():
        info = full.describe(action.id)
        assert info["usage"], f"{action.id} has no usage"
        assert info["commands"], f"{action.id} has no command preview"
        assert "describe" not in info["usage"].lower()


def test_describe_uses_real_target_when_given(full):
    info = full.describe("net.port_scan", "192.168.1.0/24", {"ports": "22,80"})
    assert info["commands"] == ["nmap -oX - -T3 --max-rate 300 -p 22,80 192.168.1.0/24"]
    assert info["example_target"] == ""  # a real target was supplied, not an example


def test_describe_uses_example_when_no_target(full):
    info = full.describe("net.host_discovery")
    assert info["example_target"] == "198.51.100.0/24"
    assert info["commands"] == ["nmap -sn -oX - 198.51.100.0/24"]


def test_describe_reflects_params(full):
    base = full.describe("net.port_scan", "10.0.0.5")
    with_ports = full.describe("net.port_scan", "10.0.0.5", {"ports": "443"})
    assert "--top-ports 1000" in base["commands"][0]
    assert "-p 443" in with_ports["commands"][0]


def test_describe_invalid_target_falls_back_to_example(full):
    info = full.describe("net.host_discovery", "not a target ;rm")
    assert info["commands"] == ["nmap -sn -oX - 198.51.100.0/24"]  # placeholder, no crash


def test_describe_marks_availability_and_tools(full):
    info = full.describe("net.port_scan", "10.0.0.5")
    assert info["tools"] == ["nmap"]
    assert info["available"] is True  # fake runner reports all tools present
    engine_missing = info  # availability string present
    assert engine_missing["availability"]


def test_builtin_actions_describe_without_a_binary(full):
    for action_id in ("web.headers", "osint.tls_cert", "pass.analyze", "vuln.prioritize"):
        info = full.describe(action_id)
        assert info["commands"][0].startswith("(")
        assert info["tools"] == []


def test_online_lookup_shows_real_url(full):
    info = full.describe("vuln.lookup", "", {"query": "apache 2.4.49"})
    assert "services.nvd.nist.gov" in info["commands"][0]
    assert "apache" in info["commands"][0]


def test_describe_never_raises_for_any_action(full):
    for action in full.actions():
        full.describe(action.id, "weird;input", {"ports": "bad", "rate": "x", "duration": "y"})

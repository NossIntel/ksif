import pytest

from core.models import Target, TargetKind
from core.validator import (
    ValidationError,
    parse_interface_target,
    parse_target,
    validate_int,
    validate_interface,
    validate_port_spec,
)


@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("192.168.1.10", TargetKind.IPV4, "192.168.1.10"),
        (" 192.168.1.0/24 ", TargetKind.CIDR, "192.168.1.0/24"),
        ("192.168.1.7/24", TargetKind.CIDR, "192.168.1.0/24"),
        ("fe80::1", TargetKind.IPV6, "fe80::1"),
        ("Example.COM", TargetKind.DOMAIN, "example.com"),
        ("localhost", TargetKind.DOMAIN, "localhost"),
        ("https://example.com:8443/a", TargetKind.URL, "https://example.com:8443/a"),
    ],
)
def test_parse_valid(raw, kind, value):
    assert parse_target(raw) == Target(kind, value)


@pytest.mark.parametrize(
    "raw",
    [
        "", "   ", "-oN /tmp/x", "--script=x", "-sV", "10.0.0.1 -p-", "a;b", "a.com\n-sV",
        "$(id)", "`id`", "a|b", "10.0.0.1,10.0.0.2", "999.1.1.1", "ftp://x.com",
        "exa_mple..com", "a" * 300, "http://", "http://user:pw@example.com",
        "http://example.com/$(id)", "http://exa mple.com", "10.0.0.0/99", "a.com\x00",
    ],
)
def test_parse_rejects(raw):
    with pytest.raises(ValidationError):
        parse_target(raw)


def test_port_spec():
    assert validate_port_spec("22, 80,1000-2000") == "22,80,1000-2000"


@pytest.mark.parametrize("raw", ["0", "70000", "80-22", "22;id", "-p22", "", "22,,80", "1-2-3"])
def test_port_spec_rejects(raw):
    with pytest.raises(ValidationError):
        validate_port_spec(raw)


@pytest.mark.parametrize("raw", ["eth0", "wlan0mon", "br-lan.10"])
def test_interface_ok(raw):
    assert validate_interface(raw) == raw
    assert parse_interface_target(raw) == Target(TargetKind.INTERFACE, raw)


@pytest.mark.parametrize("raw", ["-i", "eth0;id", "a b", "", "x" * 16])
def test_interface_rejects(raw):
    with pytest.raises(ValidationError):
        validate_interface(raw)


def test_validate_int_bounds():
    assert validate_int("30", low=1, high=300, name="duration") == 30
    for bad in ("0", "301", "abc", None):
        with pytest.raises(ValidationError):
            validate_int(bad, low=1, high=300, name="duration")

import pytest

from core.config import Scope
from core.models import Intrusiveness as I
from core.models import Mode
from core.permissions import ModeViolation, ScopeGuard, ScopeViolation
from core.validator import parse_interface_target, parse_target

DNS = {
    "example.com": ["192.168.1.9", "1.2.3.4"],
    "a.lab.test": ["192.168.1.20"],
}


def resolver(host):
    if host not in DNS:
        raise OSError("nxdomain")
    return DNS[host]


def make(mode=Mode.ACTIVE, scope=None, res=resolver):
    scope = scope or Scope(
        ips=["10.0.0.5"],
        subnets=["192.168.1.0/24", "fd00::/64"],
        domains=["example.com", "*.lab.test"],
        interfaces=["eth0"],
    )
    return ScopeGuard(scope, mode, "alice", res)


def ok(guard, raw, level=I.ACTIVE):
    return guard.authorize(parse_target(raw), level)


def test_ip_in_subnet_allowed():
    assert ok(make(), "192.168.1.77").target.value == "192.168.1.77"


def test_ip_listed_allowed():
    ok(make(), "10.0.0.5")


def test_ipv6_in_subnet_allowed():
    ok(make(), "fd00::1234")


@pytest.mark.parametrize("raw", ["8.8.8.8", "10.0.0.6", "192.168.2.1", "fd01::1"])
def test_ip_outside_blocked(raw):
    with pytest.raises(ScopeViolation):
        ok(make(), raw)


def test_cidr_subset_allowed():
    ok(make(), "192.168.1.0/28")
    ok(make(), "10.0.0.5/32")


@pytest.mark.parametrize("raw", ["192.168.0.0/16", "10.0.0.0/24", "0.0.0.0/0", "10.0.0.6/32"])
def test_cidr_wider_or_other_blocked(raw):
    with pytest.raises(ScopeViolation):
        ok(make(), raw)


def test_domain_exact_passive():
    ok(make(), "example.com", I.PASSIVE)


def test_wildcard_subdomain():
    auth = ok(make(), "a.lab.test")
    assert auth.resolved_ips == ("192.168.1.20",)


@pytest.mark.parametrize("raw", ["evilexample.com", "a.example.com", "lab.test", "evillab.test"])
def test_domain_tricks_blocked(raw):
    with pytest.raises(ScopeViolation):
        ok(make(), raw, I.PASSIVE)


def test_domain_resolving_outside_scope_blocked_when_active():
    with pytest.raises(ScopeViolation) as exc:
        ok(make(), "example.com", I.ACTIVE)
    assert "1.2.3.4" in str(exc.value)


def test_unresolvable_domain_blocked_when_active():
    scope = Scope(domains=["ghost.test"], subnets=["192.168.1.0/24"])
    with pytest.raises(ScopeViolation):
        ok(make(scope=scope), "ghost.test")


def test_domain_passive_skips_resolution():
    def boom(_):
        raise AssertionError("resolver must not be called")

    ok(make(res=boom), "example.com", I.PASSIVE)


def test_url_host_checked():
    ok(make(), "http://192.168.1.3:8080/x")
    ok(make(), "https://a.lab.test/login")
    with pytest.raises(ScopeViolation):
        ok(make(), "https://evil.com/?q=example.com")


def test_passive_mode_blocks_active():
    guard = make(mode=Mode.PASSIVE)
    with pytest.raises(ModeViolation):
        ok(guard, "192.168.1.1", I.ACTIVE)
    with pytest.raises(ModeViolation):
        ok(guard, "192.168.1.1", I.INTRUSIVE)
    ok(guard, "192.168.1.1", I.PASSIVE)


def test_empty_scope_blocks_everything():
    guard = make(scope=Scope())
    for raw in ("127.0.0.1", "192.168.1.1", "example.com", "10.0.0.0/8"):
        with pytest.raises(ScopeViolation):
            ok(guard, raw, I.PASSIVE)


def test_interface_allowlist():
    guard = make()
    guard.authorize(parse_interface_target("eth0"), I.PASSIVE)
    with pytest.raises(ScopeViolation):
        guard.authorize(parse_interface_target("wlan0"), I.PASSIVE)


def test_authorization_carries_operator():
    auth = ok(make(), "192.168.1.1")
    assert auth.operator == "alice"
    assert auth.intrusiveness is I.ACTIVE
    assert auth.issued_at.tzinfo is not None

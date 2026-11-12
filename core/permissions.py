"""Scope enforcement. ``ScopeGuard.authorize`` is the only way to obtain an
``Authorization``, and the subprocess manager refuses to run without one."""

from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from core.config import Scope
from core.models import Intrusiveness, Mode, Target, TargetKind
from core.validator import url_host

Resolver = Callable[[str], list[str]]


class ScopeViolation(PermissionError):
    """The target is not inside the authorized scope."""


class ModeViolation(PermissionError):
    """The current operating mode forbids this action."""


@dataclass(frozen=True)
class Authorization:
    """Proof that a target was checked against the scope."""

    target: Target
    intrusiveness: Intrusiveness
    operator: str
    issued_at: datetime
    resolved_ips: tuple[str, ...] = ()


def default_resolver(host: str) -> list[str]:
    """Resolve *host* to its unique IP addresses."""
    infos = socket.getaddrinfo(host, None)
    return sorted({info[4][0].split("%")[0] for info in infos})


def is_root() -> bool:
    """True when running with administrative privileges (POSIX)."""
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


class ScopeGuard:
    """Decides whether a target may be touched."""

    def __init__(
        self,
        scope: Scope,
        mode: Mode,
        operator: str,
        resolver: Resolver = default_resolver,
    ) -> None:
        self._scope = scope
        self._mode = mode
        self._operator = operator
        self._resolver = resolver
        self._ips = {ipaddress.ip_address(ip) for ip in scope.ips}
        self._nets = [ipaddress.ip_network(net) for net in scope.subnets]

    # -- primitive checks -------------------------------------------------
    def ip_in_scope(self, address: str) -> bool:
        """True when *address* is listed or inside an authorized subnet."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if ip in self._ips:
            return True
        return any(ip.version == net.version and ip in net for net in self._nets)

    def _network_in_scope(self, cidr: str) -> bool:
        net = ipaddress.ip_network(cidr)
        if any(net.version == allowed.version and net.subnet_of(allowed) for allowed in self._nets):
            return True
        return net.num_addresses == 1 and net.network_address in self._ips

    def domain_in_scope(self, name: str) -> bool:
        """Exact match, or subdomain of a ``*.`` wildcard entry."""
        name = name.lower().rstrip(".")
        for entry in self._scope.domains:
            if entry.startswith("*."):
                if name.endswith(entry[1:]) and len(name) > len(entry) - 1:
                    return True
            elif name == entry:
                return True
        return False

    # -- public API ------------------------------------------------------
    def authorize(self, target: Target, intrusiveness: Intrusiveness) -> Authorization:
        """Return an Authorization or raise ScopeViolation / ModeViolation."""
        if self._mode is Mode.PASSIVE and intrusiveness > Intrusiveness.PASSIVE:
            raise ModeViolation(
                f"passive mode blocks {intrusiveness.name.lower()} actions; "
                "switch to active mode in Configuration"
            )
        resolved: tuple[str, ...] = ()
        kind, value = target.kind, target.value
        if kind in (TargetKind.IPV4, TargetKind.IPV6):
            if not self.ip_in_scope(value):
                raise ScopeViolation(f"{value} is not in the authorized scope")
        elif kind is TargetKind.CIDR:
            if not self._network_in_scope(value):
                raise ScopeViolation(f"network {value} is not fully inside the authorized scope")
        elif kind is TargetKind.INTERFACE:
            if value not in self._scope.interfaces:
                raise ScopeViolation(f"interface {value} is not in the authorized scope")
        elif kind in (TargetKind.FILE, TargetKind.NONE):
            # Local, offline work on operator-supplied data: never touches a
            # network, so it is only ever valid as a PASSIVE action.
            if intrusiveness is not Intrusiveness.PASSIVE:
                raise ScopeViolation("local targets only support passive actions")
        elif kind in (TargetKind.DOMAIN, TargetKind.URL):
            host = url_host(target) if kind is TargetKind.URL else value
            resolved = self._authorize_host(host, intrusiveness)
        else:  # pragma: no cover - exhaustive
            raise ScopeViolation(f"unsupported target kind {kind}")
        return Authorization(target, intrusiveness, self._operator, datetime.now(UTC), resolved)

    def _authorize_host(self, host: str, intrusiveness: Intrusiveness) -> tuple[str, ...]:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not self.ip_in_scope(host):
                raise ScopeViolation(f"{host} is not in the authorized scope")
            return (host,)
        if not self.domain_in_scope(host):
            raise ScopeViolation(f"domain {host} is not in the authorized scope")
        if intrusiveness is Intrusiveness.PASSIVE:
            return ()
        try:
            addresses = self._resolver(host)
        except OSError as exc:
            raise ScopeViolation(f"cannot resolve {host}: {exc}") from exc
        if not addresses:
            raise ScopeViolation(f"cannot resolve {host}: no addresses")
        outside = [ip for ip in addresses if not self.ip_in_scope(ip)]
        if outside:
            raise ScopeViolation(
                f"{host} resolves to {', '.join(outside)}, outside the authorized IP scope"
            )
        return tuple(addresses)

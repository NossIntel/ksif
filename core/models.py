"""Typed domain models shared by every KSIF layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class TargetKind(StrEnum):
    """Kind of a validated target."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    INTERFACE = "interface"
    FILE = "file"  # local file supplied by the operator (offline work)
    NONE = "none"  # action works on already-stored data only


class Intrusiveness(IntEnum):
    """How intrusive an action is; higher values need stronger consent."""

    PASSIVE = 0
    ACTIVE = 1
    INTRUSIVE = 2


class Mode(StrEnum):
    """Global operating mode. PASSIVE blocks every non-passive action."""

    PASSIVE = "passive"
    ACTIVE = "active"


@dataclass(frozen=True)
class Target:
    """A validated, normalized target."""

    kind: TargetKind
    value: str


@dataclass
class Port:
    """An observed port on a host."""

    number: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class Host:
    """An observed network host."""

    address: str
    family: str  # "ipv4" | "ipv6"
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    os_guess: str | None = None
    os_accuracy: int | None = None
    device_type: str | None = None
    state: str = "up"
    ports: list[Port] = field(default_factory=list)
    hops: list[str] = field(default_factory=list)

"""Input validation. Every user-supplied value passes through here before
it can reach a command line, so nothing that looks like an option or shell
syntax is ever accepted."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

from core.models import Target, TargetKind

MAX_TARGET_LENGTH = 2048
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_PORT_ITEM_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
_URL_FORBIDDEN = set(";|$`<>\\'\"(){}[]^ ")
_LOCAL_NAMES = frozenset({"localhost"})


class ValidationError(ValueError):
    """Raised when an input is not a safe, well-formed value."""


def is_valid_domain(name: str) -> bool:
    """Return True when *name* is a syntactically valid lowercase hostname."""
    return name in _LOCAL_NAMES or bool(_DOMAIN_RE.match(name))


def _basic_checks(raw: str) -> str:
    if not isinstance(raw, str):
        raise ValidationError("target must be a string")
    value = raw.strip()
    if not value:
        raise ValidationError("target is empty")
    if len(value) > MAX_TARGET_LENGTH:
        raise ValidationError("target is too long")
    if value.startswith("-"):
        raise ValidationError("target must not start with '-'")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValidationError("target contains whitespace or control characters")
    return value


def _parse_url(value: str) -> Target:
    if any(ch in _URL_FORBIDDEN for ch in value):
        raise ValidationError("URL contains forbidden characters")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError as exc:
        raise ValidationError(f"malformed URL: {exc}") from exc
    if parts.scheme not in ("http", "https"):
        raise ValidationError("only http and https URLs are supported")
    if not host:
        raise ValidationError("URL has no host")
    if parts.username or parts.password:
        raise ValidationError("URLs with embedded credentials are not accepted")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not is_valid_domain(host.lower()):
            raise ValidationError("URL host is not a valid domain or IP") from None
    return Target(TargetKind.URL, value)


def parse_target(raw: str) -> Target:
    """Parse and normalize an IP, CIDR, domain or http(s) URL.

    Raises:
        ValidationError: if the value is malformed or unsafe.
    """
    value = _basic_checks(raw)
    if "://" in value:
        return _parse_url(value)
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        kind = TargetKind.IPV4 if ip.version == 4 else TargetKind.IPV6
        return Target(kind, ip.compressed)
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValidationError(f"invalid network: {value}") from exc
        return Target(TargetKind.CIDR, network.compressed)
    domain = value.lower().rstrip(".")
    if is_valid_domain(domain):
        return Target(TargetKind.DOMAIN, domain)
    raise ValidationError(f"not a valid IP, network, domain or URL: {value[:80]}")


def url_host(target: Target) -> str:
    """Return the lowercase host of a URL target."""
    host = urlsplit(target.value).hostname
    if not host:
        raise ValidationError("URL has no host")
    return host.lower()


def validate_port_spec(raw: str) -> str:
    """Validate a port list such as ``22,80,1000-2000`` and return it compact."""
    if not isinstance(raw, str):
        raise ValidationError("port spec must be a string")
    compact = "".join(raw.split())
    if not compact:
        raise ValidationError("port spec is empty")
    items = compact.split(",")
    for item in items:
        match = _PORT_ITEM_RE.match(item)
        if not match:
            raise ValidationError(f"invalid port item: {item[:20]}")
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) else low
        if not (1 <= low <= 65535 and 1 <= high <= 65535 and low <= high):
            raise ValidationError(f"port out of range: {item}")
    return ",".join(items)


def validate_interface(raw: str) -> str:
    """Validate a network interface name (e.g. ``eth0``)."""
    if not isinstance(raw, str):
        raise ValidationError("interface must be a string")
    value = raw.strip()
    if not _INTERFACE_RE.match(value) or value.startswith("-"):
        raise ValidationError("invalid interface name")
    return value


def parse_interface_target(raw: str) -> Target:
    """Return an INTERFACE target for a validated interface name."""
    return Target(TargetKind.INTERFACE, validate_interface(raw))


def validate_int(raw: object, *, low: int, high: int, name: str) -> int:
    """Coerce *raw* to an int within [low, high]."""
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{name} must be an integer") from exc
    if not low <= value <= high:
        raise ValidationError(f"{name} must be between {low} and {high}")
    return value


def parse_file_target(raw: str) -> Target:
    """Return a FILE target for an existing, readable regular file."""
    value = _basic_checks(raw.strip().strip('"')) if isinstance(raw, str) else _basic_checks(raw)
    path = Path(value).expanduser()
    if not path.is_file():
        raise ValidationError(f"file not found: {value[:120]}")
    return Target(TargetKind.FILE, str(path.resolve()))


LOCAL_TARGET = Target(TargetKind.NONE, "local")

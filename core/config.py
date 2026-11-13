"""Loading and saving of external configuration (settings and scope)."""

from __future__ import annotations

import getpass
import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.models import Mode
from core.validator import ValidationError, is_valid_domain, validate_interface

SCOPE_LIST_KEYS = ("ips", "subnets", "domains", "interfaces", "bssids", "wordpress_sites")


@dataclass
class Settings:
    """Runtime settings loaded from ``config/settings.yaml``."""

    operator: str
    mode: Mode
    rate_limit_seconds: float
    default_timeout_seconds: int
    database_path: Path
    logs_dir: Path
    reports_dir: Path
    language: str = "pt"  # UI language: "pt" or "en"


@dataclass
class Scope:
    """Authorized scope (allowlist). Empty means nothing active may run."""

    ips: list[str] = field(default_factory=list)
    subnets: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    bssids: list[str] = field(default_factory=list)
    wordpress_sites: list[str] = field(default_factory=list)
    engagement: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True when no target of any kind is authorized."""
        return not (self.ips or self.subnets or self.domains or self.interfaces or self.bssids)


def _default_operator() -> str:
    env = os.environ.get("KSIF_OPERATOR", "").strip()
    if env:
        return env
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser fails in odd containers
        return "unknown"


def _read_yaml(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        return {}, f"{path.name} not found"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        return {}, f"{path.name} is not valid YAML: {str(exc).splitlines()[0]}"
    if data is None:
        return {}, None
    if not isinstance(data, dict):
        return {}, f"{path.name} must contain a mapping at top level"
    return data, None


def load_settings(path: Path, root: Path | None = None) -> Settings:
    """Load settings; missing or broken files fall back to safe defaults."""
    base = root if root is not None else path.resolve().parent.parent
    data, _ = _read_yaml(path)
    paths = data.get("paths") if isinstance(data.get("paths"), dict) else {}
    try:
        mode = Mode(str(data.get("mode", "passive")).lower())
    except ValueError:
        mode = Mode.PASSIVE
    try:
        rate = max(0.0, float(data.get("rate_limit_seconds", 2.0)))
    except (TypeError, ValueError):
        rate = 2.0
    try:
        timeout = max(1, int(data.get("default_timeout_seconds", 600)))
    except (TypeError, ValueError):
        timeout = 600
    operator = str(data.get("operator") or "").strip() or _default_operator()
    language = "en" if str(data.get("language", "pt")).lower().startswith("en") else "pt"
    return Settings(
        operator=operator,
        mode=mode,
        rate_limit_seconds=rate,
        default_timeout_seconds=timeout,
        database_path=base / str(paths.get("database", "database/ksif.db")),
        logs_dir=base / str(paths.get("logs", "logs")),
        reports_dir=base / str(paths.get("reports", "reports")),
        language=language,
    )


def save_settings(settings: Settings, path: Path, root: Path | None = None) -> None:
    """Persist the user-editable settings back to YAML."""
    base = root if root is not None else path.resolve().parent.parent

    def rel(p: Path) -> str:
        try:
            return p.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            return str(p)

    data = {
        "operator": settings.operator,
        "mode": settings.mode.value,
        "language": settings.language,
        "rate_limit_seconds": settings.rate_limit_seconds,
        "default_timeout_seconds": settings.default_timeout_seconds,
        "paths": {
            "database": rel(settings.database_path),
            "logs": rel(settings.logs_dir),
            "reports": rel(settings.reports_dir),
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _normalize_entry(key: str, raw: Any) -> str:
    """Validate one scope entry; raise ValidationError/ValueError if invalid."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValidationError("entry must be a non-empty string")
    value = raw.strip()
    if key == "ips":
        return ipaddress.ip_address(value).compressed
    if key == "subnets":
        return ipaddress.ip_network(value, strict=False).compressed
    if key in ("domains", "wordpress_sites"):
        name = value.lower().rstrip(".")
        bare = name[2:] if key == "domains" and name.startswith("*.") else name
        if not is_valid_domain(bare):
            raise ValidationError("not a valid domain")
        return name
    if key == "interfaces":
        return validate_interface(value)
    if key == "bssids":
        parts = value.lower().replace("-", ":").split(":")
        if len(parts) != 6 or any(len(p) != 2 or not all(c in "0123456789abcdef" for c in p) for p in parts):
            raise ValidationError("not a valid BSSID")
        return ":".join(parts)
    raise ValidationError("unknown scope key")


def load_scope(path: Path) -> Scope:
    """Load the allowlist. Never raises: problems are collected in ``errors``
    and the offending entries are dropped (fail closed)."""
    data, error = _read_yaml(path)
    scope = Scope()
    if error:
        scope.errors.append(error)
        return scope
    scope.engagement = str(data.get("engagement") or "")
    for key in SCOPE_LIST_KEYS:
        raw_list = data.get(key) or []
        if not isinstance(raw_list, list):
            scope.errors.append(f"{key}: must be a list")
            continue
        clean: list[str] = getattr(scope, key)
        for raw in raw_list:
            try:
                value = _normalize_entry(key, raw)
            except ValueError as exc:  # ValidationError is a ValueError
                scope.errors.append(f"{key}: invalid entry {str(raw)[:60]!r} ({exc})")
                continue
            if value not in clean:
                clean.append(value)
    return scope

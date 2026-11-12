#!/usr/bin/env python3
"""KSIF - Kali Security Intelligence Framework. Entry point."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console

from core.config import Scope, Settings, load_scope, load_settings
from core.database import Database
from core.engine import Engine
from core.logger import AuditLogger, setup_logging
from core.subprocess_manager import SubprocessManager
from integrations.registry import self_test_all
from ui.theme import THEME

__version__ = "0.1.0"
ROOT = Path(__file__).resolve().parent
MODULES = (
    "modules.network_discovery.actions",
    "modules.osint.actions",
    "modules.web_security.actions",
    "modules.wifi_audit.actions",
    "modules.password_lab.actions",
    "modules.vulnerability_intelligence.actions",
)
DEFAULT_SETTINGS = """operator: ""
mode: passive
rate_limit_seconds: 2.0
default_timeout_seconds: 600
paths:
  database: database/ksif.db
  logs: logs
  reports: reports
"""
DEFAULT_SCOPE = """# Authorized scope (allowlist). Empty = nothing active may run.
engagement: ""
ips: []
subnets: []
domains: []
interfaces: []
bssids: []
wordpress_sites: []
"""


def ensure_config(root: Path) -> Path:
    """Create ``config/`` with safe defaults when files are missing."""
    config_dir = root / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    for name, content in (("settings.yaml", DEFAULT_SETTINGS), ("scope.yaml", DEFAULT_SCOPE)):
        path = config_dir / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")
    return config_dir


def build_engine(root: Path = ROOT) -> tuple[Engine, Database, Settings, Scope]:
    """Load configuration, open the database and register every module."""
    config_dir = ensure_config(root)
    settings = load_settings(config_dir / "settings.yaml", root)
    scope = load_scope(config_dir / "scope.yaml")
    setup_logging(settings.logs_dir)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    db = Database(settings.database_path)
    db.migrate()
    audit = AuditLogger(settings.logs_dir, db)
    engine = Engine(settings, scope, db, audit, SubprocessManager(audit))
    for name in MODULES:
        try:
            module = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name and name.startswith(exc.name):
                continue  # module not shipped in this version
            raise
        module.register(engine)
    return engine, db, settings, scope


def run_check(console: Console, engine: Engine) -> int:
    """Non-interactive health check: tools, scope and registered actions."""
    console.print(f"[ksif.title]KSIF {__version__}[/] health check")
    for row in asyncio.run(self_test_all(engine.runner)):
        style = "ksif.ok" if row["ok"] else "ksif.warn"
        state = "ok     " if row["ok"] else "missing"
        console.print(f"  [{style}]{state}[/] {row['tool']:<16} {row['detail']}", markup=True, highlight=False)
    scope = engine.scope
    console.print(f"mode: {engine.settings.mode.value}   operator: {engine.settings.operator}", highlight=False)
    if scope.is_empty:
        console.print("[ksif.warn]scope: EMPTY - active operations are blocked (edit config/scope.yaml)[/]")
    else:
        console.print(
            f"scope: {len(scope.ips)} ip(s), {len(scope.subnets)} subnet(s), {len(scope.domains)} domain(s), "
            f"{len(scope.interfaces)} interface(s)", highlight=False)
    for error in scope.errors:
        console.print(f"[ksif.err]scope problem:[/] {error}", highlight=False)
    console.print(f"actions registered: {len(engine.actions())}", highlight=False)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(prog="ksif", description="Kali Security Intelligence Framework")
    parser.add_argument("--version", action="version", version=f"KSIF {__version__}")
    parser.add_argument("--check", action="store_true", help="check tools and configuration, then exit")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    console = Console(theme=THEME)
    engine, db, _settings, _scope = build_engine(args.root)
    try:
        if args.check:
            return run_check(console, engine)
        from ui.app import App  # imported late so --check works without a TTY

        return App(engine, console, config_dir=args.root / "config").run()
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())

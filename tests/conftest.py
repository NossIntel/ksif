"""Shared fixtures. ``FakeToolRunner`` executes ``tests/fake_tool.py`` instead
of the real binaries, so the full pipeline (authorization, process spawn,
streaming, parsing, persistence) is exercised with recorded tool output."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from core.config import Scope, Settings
from core.database import Database
from core.engine import Engine
from core.logger import AuditLogger
from core.models import Mode
from core.subprocess_manager import ALLOWED_BINARIES, SubprocessManager

FIXTURES = Path(__file__).parent / "fixtures"
FAKE_TOOL = Path(__file__).parent / "fake_tool.py"


class FakeToolRunner(SubprocessManager):
    """Spawns ``python fake_tool.py <fixtures-dir> <binary> <args...>``."""

    def __init__(self, audit, fixtures_dir: Path, available: set[str] | None = None):
        names = available if available is not None else set(ALLOWED_BINARIES)
        super().__init__(audit, resolve=lambda name: sys.executable if name in names else None)
        self.fixtures_dir = fixtures_dir

    def _argv(self, binary, path, args):
        return [sys.executable, str(FAKE_TOOL), str(self.fixtures_dir), binary, *args]


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        operator="tester", mode=Mode.ACTIVE, rate_limit_seconds=0.0, default_timeout_seconds=30,
        database_path=tmp_path / "db" / "ksif.db", logs_dir=tmp_path / "logs",
        reports_dir=tmp_path / "reports",
    )


@pytest.fixture
def scope() -> Scope:
    return Scope(
        ips=["10.0.0.5"], subnets=["192.168.1.0/24", "127.0.0.0/8"],
        domains=["example.com", "*.lab.test", "localhost"], interfaces=["eth0", "wlan0"],
        bssids=["aa:bb:cc:dd:ee:ff"], wordpress_sites=["blog.lab.test"], engagement="Unit test lab",
    )


@pytest.fixture
def db():
    database = Database(":memory:")
    database.migrate()
    yield database
    database.close()


@pytest.fixture
def audit(settings, db) -> AuditLogger:
    return AuditLogger(settings.logs_dir, db)


@pytest.fixture
def fake_dir(tmp_path) -> Path:
    """Directory where a test drops ``<binary>.out`` files for the fake tool."""
    path = tmp_path / "fake"
    path.mkdir()
    return path


class FakeHttp:
    """Stand-in for AuthorizedHttpClient. Scripted responses keyed by URL."""

    def __init__(self, responses=None, tls=None):
        self.responses = responses or {}
        self.tls = tls
        self.requested: list[str] = []

    def base_url(self, authorization, scheme="https"):
        from core.models import TargetKind
        if authorization.target.kind is TargetKind.URL:
            return authorization.target.value
        return f"{scheme}://{authorization.target.value}/"

    def fetch(self, url, authorization, *, method="GET", timeout=None):
        self.requested.append(url)
        if url in self.responses:
            return self.responses[url]
        from core.http import HttpResponse
        return HttpResponse(url=url, status=200, headers={}, body="", final_url=url)

    def tls_info(self, authorization, port=443):
        from core.http import TlsInfo
        host = authorization.target.value
        return self.tls or TlsInfo(host=host, port=port, protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384")


class FakeIntel:
    """Stand-in for IntelHttpClient. Scripted JSON keyed by URL substring."""

    def __init__(self, payloads=None):
        self.payloads = payloads or {}
        self.requested: list[str] = []

    def get_json(self, url, operator="system"):
        self.requested.append(url)
        for fragment, payload in self.payloads.items():
            if fragment in url:
                return payload
        return None


@pytest.fixture
def make_engine(settings, scope, db, audit, fake_dir):
    """Factory for an Engine wired to the fake tool runner."""

    def factory(*, root=True, available=None, resolver=None, mode=None, http=None, intel=None):
        if mode is not None:
            settings.mode = mode
        runner = FakeToolRunner(audit, fake_dir, available)
        return Engine(
            settings, scope, db, audit, runner, root_check=lambda: root,
            resolver=resolver or (lambda host: ["192.168.1.20"]),
            http=http, intel=intel,
        )

    return factory


def events(db: Database) -> list[str]:
    return [row["event"] for row in db.list_audit(500)]

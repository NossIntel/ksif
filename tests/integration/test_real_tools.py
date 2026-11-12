"""Integration tests against the REAL tools. Only loopback is ever targeted.

Run on Kali:  .venv/bin/python -m pytest -m integration -v
Each test skips (with the reason) when its tool is not installed.
"""

from __future__ import annotations

import shutil

import pytest

from core.config import Scope
from core.engine import Engine
from core.logger import AuditLogger
from core.models import Mode
from core.permissions import is_root
from core.subprocess_manager import SubprocessManager
from integrations.registry import all_integrations
from modules.network_discovery import actions

pytestmark = pytest.mark.integration


def need(tool: str) -> None:
    if shutil.which(tool) is None:
        pytest.skip(f"{tool} is not installed")


@pytest.fixture
def real_engine(settings, db):
    settings.mode = Mode.ACTIVE
    settings.default_timeout_seconds = 180
    scope = Scope(ips=["127.0.0.1"], engagement="integration test (loopback only)")
    audit = AuditLogger(settings.logs_dir, db)
    engine = Engine(settings, scope, db, audit, SubprocessManager(audit))
    actions.register(engine)
    return engine


def yes(_prompt: str) -> bool:
    return True


@pytest.mark.parametrize("binary", ["nmap", "arp-scan", "masscan", "tshark"])
async def test_self_test_reports_a_version(real_engine, binary):
    need(binary)
    tool = next(t for _label, t in all_integrations(real_engine.runner) if t.binary == binary)
    ok, detail = await tool.self_test()
    assert ok, detail
    assert detail[0].isdigit()


async def test_nmap_host_discovery_localhost(real_engine, db):
    need("nmap")
    result = await real_engine.execute("net.host_discovery", "127.0.0.1", confirm=yes)
    assert result.status == "completed", result.error
    assert [h.address for h in db.list_hosts(result.op_id)] == ["127.0.0.1"]
    operation = db.get_operation(result.op_id)
    assert operation["command"].startswith("nmap -sn")


async def test_nmap_port_scan_localhost_parses(real_engine, db):
    need("nmap")
    result = await real_engine.execute("net.port_scan", "127.0.0.1", {"ports": "1-1024"}, confirm=yes)
    assert result.status == "completed", result.error
    hosts = db.list_hosts(result.op_id)
    assert len(hosts) == 1 and hosts[0].address == "127.0.0.1"
    for port in hosts[0].ports:
        assert 1 <= port.number <= 1024 and port.state.startswith("open")


async def test_nmap_service_and_os_detection_localhost(real_engine, db):
    need("nmap")
    if not is_root():
        pytest.skip("OS detection needs root")
    result = await real_engine.execute("net.service_os", "127.0.0.1", {"ports": "1-1024"}, confirm=yes)
    assert result.status == "completed", result.error


async def test_out_of_scope_never_spawns_a_process(real_engine, db):
    need("nmap")
    result = await real_engine.execute("net.port_scan", "8.8.8.8", confirm=yes)
    assert result.status == "blocked"
    assert "command_started" not in [row["event"] for row in db.list_audit(100)]

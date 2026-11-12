import re
import sys
from pathlib import Path

import pytest

from core.models import Intrusiveness
from core.permissions import ScopeGuard
from core.subprocess_manager import (
    ALLOWED_BINARIES,
    BinaryNotAllowed,
    ProcessTimeout,
    SubprocessManager,
    ToolNotFound,
    UnauthorizedExecution,
)
from core.validator import parse_target
from tests.conftest import events

TARGET = "192.168.1.5"


@pytest.fixture
def auth(scope, settings):
    guard = ScopeGuard(scope, settings.mode, "tester")
    return guard.authorize(parse_target(TARGET), Intrusiveness.ACTIVE)


@pytest.fixture
def runner(audit):
    return SubprocessManager(audit, allowed=frozenset({"py"}), resolve=lambda _n: sys.executable)


def script(code):
    return ["-c", code, TARGET]


async def test_runs_and_captures_output(runner, auth):
    result = await runner.run("py", script("import sys; print('hi', sys.argv[1]); sys.stderr.write('warn')"),
                              authorization=auth, timeout=20)
    assert result.returncode == 0
    assert result.stdout.strip() == f"hi {TARGET}"
    assert result.stderr == "warn"
    assert result.command[0] == "py"


async def test_streams_lines(runner, auth):
    seen = []
    await runner.run("py", script("print('a'); print('b')"), authorization=auth, timeout=20, on_line=seen.append)
    assert seen == ["a", "b"]


async def test_nonzero_exit_code_returned(runner, auth):
    result = await runner.run("py", script("import sys; sys.exit(3)"), authorization=auth, timeout=20)
    assert result.returncode == 3


async def test_disallowed_binary(audit, auth):
    manager = SubprocessManager(audit, resolve=lambda _n: sys.executable)
    for binary in ("bash", "sh", "python", "aireplay-ng", "hydra"):
        with pytest.raises(BinaryNotAllowed):
            await manager.run(binary, [TARGET], authorization=auth, timeout=5)
        with pytest.raises(BinaryNotAllowed):
            await manager.probe(binary, "--version")
        assert not manager.is_available(binary)


def test_default_allowlist_excludes_attack_tools():
    forbidden = {"aireplay-ng", "mdk3", "mdk4", "hydra", "medusa", "ncrack", "wifite", "reaver",
                 "bully", "sh", "bash", "zsh", "python", "python3", "curl", "wget", "nc", "msfconsole",
                 "sqlmap", "aircrack-ng", "bettercap", "ettercap"}
    assert not forbidden & ALLOWED_BINARIES


async def test_missing_tool(audit, auth):
    manager = SubprocessManager(audit, resolve=lambda _n: None)
    assert not manager.is_available("nmap")
    with pytest.raises(ToolNotFound):
        await manager.run("nmap", [TARGET], authorization=auth, timeout=5)


async def test_requires_target_in_args(runner, auth):
    with pytest.raises(UnauthorizedExecution):
        await runner.run("py", ["-c", "print(1)", "8.8.8.8"], authorization=auth, timeout=5)
    with pytest.raises(UnauthorizedExecution):  # substring is not enough
        await runner.run("py", ["-c", "print(1)", TARGET + "0"], authorization=auth, timeout=5)
    with pytest.raises(UnauthorizedExecution):
        await runner.run("py", script("print(1)"), authorization=None, timeout=5)


@pytest.mark.parametrize("bad", ["a\nb", "a\x00b", "", 5])
async def test_rejects_bad_args(runner, auth, bad):
    with pytest.raises(ValueError):
        await runner.run("py", ["-c", "print(1)", bad, TARGET], authorization=auth, timeout=5)


async def test_timeout_kills_process(runner, auth):
    code = "import time,sys; print('partial'); sys.stdout.flush(); time.sleep(30)"
    with pytest.raises(ProcessTimeout) as exc:
        await runner.run("py", script(code), authorization=auth, timeout=1.5)
    assert "partial" in exc.value.partial_output


async def test_probe_rejects_other_args(runner):
    with pytest.raises(UnauthorizedExecution):
        await runner.probe("py", "-c")
    result = await runner.probe("py", "--version")
    assert "Python" in result.stdout + result.stderr


async def test_shell_metachar_is_literal(runner, auth):
    result = await runner.run(
        "py", ["-c", "import sys; print(sys.argv[1])", "; echo pwned && whoami", TARGET],
        authorization=auth, timeout=20,
    )
    assert result.stdout.strip() == "; echo pwned && whoami"


async def test_audit_events_recorded(runner, auth, db):
    await runner.run("py", script("print(1)"), authorization=auth, timeout=20)
    assert events(db)[:2] == ["command_finished", "command_started"]
    started = db.list_audit()[1]
    assert started["operator"] == "tester" and started["detail"]["target"] == TARGET


def test_no_raw_process_spawning_outside_manager():
    root = Path(__file__).parent.parent
    pattern = re.compile(
        r"shell\s*=\s*True|os\.system|os\.popen|import subprocess|from subprocess|create_subprocess|"
        r"\bpty\.|os\.exec|os\.spawn"
    )
    offenders = []
    files = [root / "main.py"]
    for folder in ("core", "integrations", "modules", "ui"):
        files += list((root / folder).rglob("*.py"))
    for path in files:
        if not path.exists() or path.name == "subprocess_manager.py":
            continue
        if pattern.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(root)))
    assert offenders == []

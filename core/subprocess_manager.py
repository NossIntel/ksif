"""The single place where KSIF starts external processes.

Guarantees:
* never a shell - arguments are passed as a list to ``exec``;
* only binaries from a fixed allowlist;
* every run needs an ``Authorization`` whose target appears verbatim in the
  argument list (version probes are the only exception);
* every command is written to the audit trail.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from core.logger import AuditLogger
from core.models import TargetKind
from core.permissions import Authorization

# Tools KSIF is allowed to execute. Attack tooling (aireplay-ng, mdk4, hydra,
# medusa, ...) and shells are deliberately absent and must never be added.
ALLOWED_BINARIES: frozenset[str] = frozenset(
    {
        # 01 network discovery
        "nmap", "arp-scan", "masscan", "tshark",
        # 02 osint
        "whois", "dig", "dnsrecon", "subfinder", "amass", "theHarvester",
        # 03 web security
        "whatweb", "nikto", "nuclei", "wpscan",
        # 04 wi-fi (passive listing only)
        "nmcli", "iw",
        # 05 password lab (offline auditing of operator-supplied hashes only)
        "john", "hashcat",
    }
)
PROBE_ARGS: frozenset[str] = frozenset(
    {"--version", "-V", "-v", "--help", "-version", "-Version", "version", "-h"}
)


class BinaryNotAllowed(PermissionError):
    """The binary is not on the allowlist."""


class ToolNotFound(FileNotFoundError):
    """The binary is allowed but not installed."""


class UnauthorizedExecution(PermissionError):
    """No valid authorization covers this command."""


class ProcessTimeout(TimeoutError):
    """The process exceeded its timeout and was killed."""

    def __init__(self, message: str, partial_output: str = "") -> None:
        super().__init__(message)
        self.partial_output = partial_output


@dataclass
class ProcessResult:
    """Outcome of a finished process."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float


class SubprocessManager:
    """Runs allowlisted tools without a shell, under authorization."""

    def __init__(
        self,
        audit: AuditLogger,
        *,
        allowed: frozenset[str] = ALLOWED_BINARIES,
        resolve: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self._audit = audit
        self._allowed = allowed
        self._resolve = resolve

    def is_available(self, binary: str) -> bool:
        """True when *binary* is allowlisted and installed."""
        return binary in self._allowed and self._resolve(binary) is not None

    def _locate(self, binary: str) -> str:
        if binary not in self._allowed:
            raise BinaryNotAllowed(f"{binary!r} is not an allowed tool")
        path = self._resolve(binary)
        if path is None:
            raise ToolNotFound(f"{binary} is not installed")
        return path

    def _argv(self, binary: str, path: str, args: Sequence[str]) -> list[str]:
        """Final argv. Overridable so tests can substitute a fake tool."""
        return [path, *args]

    @staticmethod
    def _check_args(args: Sequence[str]) -> list[str]:
        clean: list[str] = []
        for arg in args:
            if not isinstance(arg, str) or not arg:
                raise ValueError("arguments must be non-empty strings")
            if "\x00" in arg or "\n" in arg or "\r" in arg:
                raise ValueError("arguments must not contain NUL or line breaks")
            clean.append(arg)
        return clean

    async def probe(self, binary: str, arg: str, timeout: float = 15) -> ProcessResult:
        """Run a harmless version/help probe (no target, no authorization)."""
        if arg not in PROBE_ARGS:
            raise UnauthorizedExecution(f"{arg!r} is not a permitted probe argument")
        path = self._locate(binary)
        return await self._execute(binary, path, [arg], timeout, None, operator="system", target=None)

    async def run(
        self,
        binary: str,
        args: Sequence[str],
        *,
        authorization: Authorization,
        timeout: float,
        on_line: Callable[[str], None] | None = None,
    ) -> ProcessResult:
        """Run *binary* against the authorized target.

        Raises:
            BinaryNotAllowed, ToolNotFound, UnauthorizedExecution, ProcessTimeout, ValueError
        """
        path = self._locate(binary)
        clean = self._check_args(args)
        if not isinstance(authorization, Authorization):
            raise UnauthorizedExecution("a scope authorization is required")
        # A NONE target is a local-only action (e.g. listing nearby Wi-Fi): there
        # is no remote target to pin to an argument. Every other kind must appear
        # verbatim, so a tool can never be pointed at something unauthorized.
        if authorization.target.kind is not TargetKind.NONE and authorization.target.value not in clean:
            raise UnauthorizedExecution(
                "the authorized target does not appear in the command arguments"
            )
        return await self._execute(
            binary, path, clean, timeout, on_line,
            operator=authorization.operator, target=authorization.target.value,
        )

    async def _execute(
        self,
        binary: str,
        path: str,
        args: list[str],
        timeout: float,
        on_line: Callable[[str], None] | None,
        *,
        operator: str,
        target: str | None,
    ) -> ProcessResult:
        argv = self._argv(binary, path, args)
        logical = [binary, *args]
        self._audit.record("command_started", operator=operator, command=logical, target=target)
        started = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_lines: list[str] = []
        err_lines: list[str] = []

        async def pump(stream: asyncio.StreamReader | None, sink: list[str], notify: bool) -> None:
            if stream is None:
                return
            while True:
                try:
                    raw = await stream.readline()
                except ValueError:  # line longer than the stream limit
                    raw = await stream.read(65536)
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace")
                sink.append(line)
                if notify and on_line is not None:
                    on_line(line.rstrip("\r\n"))

        async def wait_all() -> None:
            await asyncio.gather(pump(proc.stdout, out_lines, True), pump(proc.stderr, err_lines, False))
            await proc.wait()

        try:
            await asyncio.wait_for(wait_all(), timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            duration = time.monotonic() - started
            self._audit.record(
                "command_finished", operator=operator, command=logical, target=target,
                returncode=None, timed_out=True, duration=round(duration, 2),
            )
            raise ProcessTimeout(
                f"{binary} exceeded {timeout:g}s and was killed", "".join(out_lines)
            ) from None
        duration = time.monotonic() - started
        returncode = proc.returncode if proc.returncode is not None else -1
        self._audit.record(
            "command_finished", operator=operator, command=logical, target=target,
            returncode=returncode, timed_out=False, duration=round(duration, 2),
        )
        return ProcessResult(logical, returncode, "".join(out_lines), "".join(err_lines), duration)

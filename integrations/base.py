"""Common contract for every external tool integration."""

from __future__ import annotations

import re
from abc import ABC
from typing import ClassVar

from core.subprocess_manager import BinaryNotAllowed, ProcessTimeout, SubprocessManager, ToolNotFound


class ParseError(ValueError):
    """Tool output could not be interpreted (incomplete or unexpected)."""


class ToolIntegration(ABC):
    """An external tool: detection, a real self-test, typed command builders
    and output parsers. Subclasses never accept free-form flags from users."""

    binary: ClassVar[str]
    install_hint: ClassVar[str] = ""
    probe_arg: ClassVar[str] = "--version"
    version_pattern: ClassVar[str] = r"(\d+\.\d+(?:\.\d+)*)"

    def __init__(self, runner: SubprocessManager) -> None:
        self.runner = runner

    def is_available(self) -> bool:
        """True when the binary is installed."""
        return self.runner.is_available(self.binary)

    def parse_version(self, output: str) -> str | None:
        """Extract the version number from the probe output."""
        match = re.search(self.version_pattern, output)
        return match.group(1) if match else None

    async def version(self) -> str | None:
        """Run the tool's version probe and return the parsed version."""
        try:
            result = await self.runner.probe(self.binary, self.probe_arg)
        except (ToolNotFound, BinaryNotAllowed, ProcessTimeout, OSError):
            return None
        return self.parse_version(result.stdout + "\n" + result.stderr)

    async def self_test(self) -> tuple[bool, str]:
        """Really execute the tool (harmless probe) and report the outcome."""
        if not self.is_available():
            return False, f"not installed ({self.install_hint})" if self.install_hint else "not installed"
        try:
            result = await self.runner.probe(self.binary, self.probe_arg)
        except ProcessTimeout:
            return False, "probe timed out"
        except OSError as exc:
            return False, f"cannot execute: {exc}"
        version = self.parse_version(result.stdout + "\n" + result.stderr)
        if version is None:
            return False, f"unexpected output from '{self.binary} {self.probe_arg}'"
        return True, version

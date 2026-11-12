"""John the Ripper integration for offline auditing of your OWN password hashes.

This is a strength-auditing use: you provide a file of hashes you are
authorized to assess and a wordlist, and KSIF reports which ones are weak
enough to be recovered from that list. It runs entirely offline. KSIF does not
provide any online or network password attack.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.models import Target, TargetKind
from core.validator import ValidationError
from integrations.base import ToolIntegration

_FORMAT_RE = re.compile(r"^[A-Za-z0-9\-]{1,32}$")


def _validate_format(fmt: str | None) -> str | None:
    if not fmt:
        return None
    if not _FORMAT_RE.match(fmt):
        raise ValidationError("invalid hash format name")
    return fmt


def _validate_wordlist(path: str) -> str:
    candidate = Path(path).expanduser()
    if not candidate.is_file():
        raise ValidationError(f"wordlist not found: {path[:120]}")
    return str(candidate.resolve())


class JohnIntegration(ToolIntegration):
    """Wrapper around ``john`` (offline, dictionary-based auditing only)."""

    binary = "john"
    install_hint = "sudo apt install john"
    probe_arg = "--help"
    version_pattern = r"John the Ripper (\S+)"

    def crack_args(self, target: Target, wordlist: str, fmt: str | None = None) -> list[str]:
        """Dictionary run against a hash file the operator supplied."""
        if target.kind is not TargetKind.FILE:
            raise ValidationError("john needs a hash file target")
        args = [f"--wordlist={_validate_wordlist(wordlist)}"]
        clean = _validate_format(fmt)
        if clean:
            args.append(f"--format={clean}")
        args.append(target.value)
        return args

    def show_args(self, target: Target, fmt: str | None = None) -> list[str]:
        """Show which hashes have been recovered."""
        args = ["--show"]
        clean = _validate_format(fmt)
        if clean:
            args.append(f"--format={clean}")
        args.append(target.value)
        return args

    def parse_show(self, output: str) -> dict[str, int]:
        """Parse ``john --show``: how many hashes were cracked and how many remain."""
        cracked = left = 0
        summary = re.search(r"(\d+)\s+password hash(?:es)?\s+cracked,\s+(\d+)\s+left", output)
        if summary:
            cracked, left = int(summary.group(1)), int(summary.group(2))
        return {"cracked": cracked, "remaining": left}

    def parse_version(self, output: str) -> str | None:
        match = re.search(r"John the Ripper (\d+\.\d+[^\s,]*)", output)
        return match.group(1) if match else None

"""Offline password-strength analysis (pure functions, no I/O, no network).

This evaluates how robust a password is - its entropy, character variety and
whether it matches well-known weak patterns - so you can set and verify a
sensible policy. It does not transmit anything anywhere.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# A small, widely published set of the most common weak passwords.
COMMON_PASSWORDS = frozenset({
    "password", "123456", "123456789", "12345678", "12345", "qwerty", "abc123",
    "password1", "111111", "123123", "admin", "letmein", "welcome", "monkey",
    "iloveyou", "000000", "qwerty123", "1q2w3e4r", "dragon", "sunshine",
    "princess", "football", "charlie", "aa123456", "root", "toor", "changeme",
})
_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "01234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")


@dataclass
class Strength:
    """Result of analysing one password."""

    length: int
    entropy_bits: float
    classes: int
    verdict: str  # very weak | weak | fair | strong | very strong
    issues: list[str] = field(default_factory=list)

    @property
    def is_weak(self) -> bool:
        return self.verdict in ("very weak", "weak")


def _pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32
    return pool or 1


def entropy_bits(password: str) -> float:
    """Shannon-style upper bound: length x log2(character pool)."""
    return round(len(password) * math.log2(_pool_size(password)), 1) if password else 0.0


def _has_sequence(password: str) -> bool:
    low = password.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in low or seq[i:i + 4][::-1] in low:
                return True
    return False


def analyze(password: str, min_length: int = 12) -> Strength:
    """Analyse one password against a minimum-length policy."""
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    bits = entropy_bits(password)
    issues: list[str] = []
    if len(password) < min_length:
        issues.append(f"shorter than the {min_length}-character policy")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("appears in common-password lists")
        bits = min(bits, 10.0)
    if classes <= 1:
        issues.append("uses a single character class")
    if re.fullmatch(r"(.)\1*", password or " "):
        issues.append("is a single repeated character")
    if _has_sequence(password):
        issues.append("contains a keyboard or alphabet sequence")
    if re.fullmatch(r"\d+", password or "x"):
        issues.append("is all digits")

    if bits < 28:
        verdict = "very weak"
    elif bits < 40:
        verdict = "weak"
    elif bits < 60:
        verdict = "fair"
    elif bits < 128:
        verdict = "strong"
    else:
        verdict = "very strong"

    # Obvious weak patterns override the raw entropy estimate.
    order = ["very weak", "weak", "fair", "strong", "very strong"]
    repeated = password and re.fullmatch(r"(.)\1*", password)
    if password.lower() in COMMON_PASSWORDS or repeated:
        verdict = "very weak"
    elif _has_sequence(password) or re.fullmatch(r"\d+", password or "x") or classes <= 1:
        verdict = order[min(order.index(verdict), order.index("weak"))]
    return Strength(len(password), bits, classes, verdict, issues)


@dataclass
class PolicyReport:
    """Aggregate statistics for a list of passwords."""

    total: int
    weak: int
    too_short: int
    reused: int
    common: int
    average_entropy: float
    weakest_examples: list[str] = field(default_factory=list)


def audit_list(passwords: list[str], min_length: int = 12) -> PolicyReport:
    """Summarise a list of passwords against a policy (values are not retained)."""
    seen: dict[str, int] = {}
    weak = too_short = common = 0
    total_entropy = 0.0
    weakest: list[tuple[float, str]] = []
    for raw in passwords:
        pw = raw.rstrip("\n")
        if not pw:
            continue
        seen[pw] = seen.get(pw, 0) + 1
        result = analyze(pw, min_length)
        total_entropy += result.entropy_bits
        if result.is_weak:
            weak += 1
        if len(pw) < min_length:
            too_short += 1
        if pw.lower() in COMMON_PASSWORDS:
            common += 1
        weakest.append((result.entropy_bits, _mask(pw)))
    counted = sum(seen.values())
    reused = sum(count for count in seen.values() if count > 1)
    weakest.sort(key=lambda item: item[0])
    return PolicyReport(
        total=counted, weak=weak, too_short=too_short, reused=reused, common=common,
        average_entropy=round(total_entropy / counted, 1) if counted else 0.0,
        weakest_examples=[label for _bits, label in weakest[:5]],
    )


def _mask(password: str) -> str:
    """A non-reversible label for a password (first char + length)."""
    if not password:
        return "(empty)"
    return f"{password[0]}{'*' * (len(password) - 1)} (len {len(password)})"

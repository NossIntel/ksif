"""Password Security Lab actions (module 05).

Everything here is offline and limited to material you control: a password you
type to test, a list of passwords you own, or a file of hashes you are
authorized to audit. KSIF performs no online password attack against any
service, network or account.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.engine import Action, ActionContext, ActionOutput, Engine
from core.models import Finding, Intrusiveness, TargetKind
from integrations.john import JohnIntegration, _validate_wordlist
from modules.password_lab import strength

MODULE = "password_lab"
NONE = frozenset({TargetKind.NONE})
FILE = frozenset({TargetKind.FILE})
_READ_LIMIT = 5_000_000  # bytes


def _read_lines(path: str) -> list[str]:
    data = Path(path).read_text(encoding="utf-8", errors="replace")[:_READ_LIMIT]
    return data.splitlines()


async def analyze_password(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Rate one password typed by the operator. The password is never stored."""
    password = str(params.get("password", ""))
    if not password:
        raise ValueError("no password supplied")
    min_length = _int(params.get("min_length"), 12)
    result = strength.analyze(password, min_length)
    findings = []
    if result.is_weak:
        findings.append(Finding(MODULE, "password", "medium",
                                f"Password rated '{result.verdict}'", "operator input",
                                evidence=f"{result.entropy_bits} bits; " + "; ".join(result.issues),
                                recommendation="Use a longer passphrase with mixed character classes."))
    return ActionOutput(findings=findings,
                        summary=f"verdict: {result.verdict} ({result.entropy_bits} bits)",
                        data={"verdict": result.verdict, "entropy_bits": result.entropy_bits,
                              "length": result.length, "classes": result.classes, "issues": result.issues})


async def policy_audit(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Audit a file of passwords you own against a minimum-length policy."""
    min_length = _int(params.get("min_length"), 12)
    report = strength.audit_list(_read_lines(ctx.target.value), min_length)
    findings = []
    if report.weak:
        pct = round(100 * report.weak / report.total) if report.total else 0
        findings.append(Finding(MODULE, "policy", "high" if pct >= 30 else "medium",
                                f"{report.weak}/{report.total} passwords are weak ({pct}%)",
                                Path(ctx.target.value).name,
                                evidence=f"avg entropy {report.average_entropy} bits; "
                                         f"{report.common} common, {report.reused} reused",
                                recommendation="Enforce length >= 12, block common passwords, "
                                               "and require a password manager."))
    return ActionOutput(findings=findings,
                        summary=f"{report.total} password(s): {report.weak} weak, {report.common} common",
                        data={"total": report.total, "weak": report.weak, "too_short": report.too_short,
                              "reused": report.reused, "common": report.common,
                              "average_entropy": report.average_entropy,
                              "weakest_examples": report.weakest_examples})


async def compromised_check(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Compare a password list you own against a local known-compromised list."""
    breached_path = str(params.get("wordlist") or params.get("breached") or "")
    if not breached_path:
        raise ValueError("provide 'wordlist': path to a local known-compromised password list")
    breached = {line.rstrip("\n") for line in _read_lines(_validate_wordlist(breached_path))}
    mine = _read_lines(ctx.target.value)
    hits = sorted({pw for pw in mine if pw and pw in breached})
    findings = []
    if hits:
        findings.append(Finding(MODULE, "exposure", "critical",
                                f"{len(hits)} password(s) appear in the compromised list",
                                Path(ctx.target.value).name,
                                evidence=f"{len(hits)} of {len([m for m in mine if m])} checked",
                                recommendation="Reset every matched password immediately; they are public."))
    return ActionOutput(findings=findings,
                        summary=f"{len(hits)} compromised password(s) found",
                        data={"checked": len([m for m in mine if m]), "compromised": len(hits)})


async def hash_audit(ctx: ActionContext, params: dict[str, Any]) -> ActionOutput:
    """Audit your own password hashes offline with John the Ripper + a wordlist."""
    wordlist = str(params.get("wordlist", ""))
    if not wordlist:
        raise ValueError("provide 'wordlist': path to a dictionary file")
    fmt = str(params.get("format", "")) or None
    tool = JohnIntegration(ctx.runner)
    timeout = ctx.settings.default_timeout_seconds
    crack = await ctx.runner.run("john", tool.crack_args(ctx.target, wordlist, fmt),
                                 authorization=ctx.authorization, timeout=timeout, on_line=ctx.on_line)
    show = await ctx.runner.run("john", tool.show_args(ctx.target, fmt),
                                authorization=ctx.authorization, timeout=max(30, timeout // 4))
    ctx.save_raw(crack.stdout + "\n--- show ---\n" + show.stdout, "txt", crack.command)
    stats = tool.parse_show(show.stdout)
    total = stats["cracked"] + stats["remaining"]
    findings = []
    if stats["cracked"]:
        pct = round(100 * stats["cracked"] / total) if total else 0
        findings.append(Finding(MODULE, "hashes", "high",
                                f"{stats['cracked']}/{total} hashes recovered from the wordlist ({pct}%)",
                                Path(ctx.target.value).name,
                                recommendation="Force a reset of the weak accounts and raise password "
                                               "requirements; consider a slow hash (bcrypt/argon2)."))
    return ActionOutput(findings=findings,
                        summary=f"{stats['cracked']} of {total} hashes are weak",
                        data=stats)


def _int(value: object, default: int) -> int:
    try:
        return max(1, int(str(value)))
    except (TypeError, ValueError):
        return default


def register(engine: Engine) -> None:
    """Register every Password Lab action (all offline/passive)."""
    p = Intrusiveness.PASSIVE
    attest = "I own, or am authorized to audit, this password/hash material"
    specs = [
        ("pass.analyze", "Analyse one password", NONE, (), analyze_password, ("password", "min_length"),
         "Entropy and policy check for a single password (not stored)", ""),
        ("pass.policy_audit", "Audit a password list", FILE, (), policy_audit, ("min_length",),
         "Policy statistics for a password list you own", attest),
        ("pass.compromised", "Check against a compromised list", FILE, (), compromised_check, ("wordlist",),
         "Match your passwords against a local breach list", attest),
        ("pass.hash_audit", "Audit your own hashes (john)", FILE, ("john",), hash_audit,
         ("wordlist", "format"), "Offline dictionary audit of hashes you own", attest),
    ]
    for ident, title, kinds, tools, handler, prms, desc, consent in specs:
        engine.register(Action(id=ident, module=MODULE, title=title, intrusiveness=p, target_kinds=kinds,
                               required_tools=tools, requires_root=False, handler=handler, params=prms,
                               description=desc, consent=consent))

"""Operation engine: the only entry point the UI uses to do anything.

Lifecycle of one operation:
validate target -> scope/mode check -> tools/root check -> operator
confirmation -> rate limit -> run handler -> persist -> audit.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.config import Scope, Settings
from core.database import Database
from core.http import AuthorizedHttpClient, IntelHttpClient
from core.logger import LOGGER_NAME, AuditLogger
from core.models import Finding, Host, Intrusiveness, Mode, Target, TargetKind
from core.permissions import (
    Authorization,
    ModeViolation,
    Resolver,
    ScopeGuard,
    ScopeViolation,
    default_resolver,
    is_root,
)
from core.subprocess_manager import SubprocessManager
from core.validator import (
    LOCAL_TARGET,
    ValidationError,
    parse_file_target,
    parse_interface_target,
    parse_target,
)

log = logging.getLogger(LOGGER_NAME)


class RateLimiter:
    """Enforces a minimum interval between operations."""

    def __init__(
        self,
        min_interval: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.min_interval = max(0.0, min_interval)
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    async def wait(self) -> None:
        """Sleep until *min_interval* has passed since the previous call."""
        now = self._clock()
        if self._last is not None:
            remaining = self.min_interval - (now - self._last)
            if remaining > 0:
                await self._sleep(remaining)
                now = self._clock()
        self._last = now


@dataclass
class ActionContext:
    """Everything a handler may use. Handlers never build their own runner."""

    authorization: Authorization
    runner: SubprocessManager
    db: Database
    settings: Settings
    scope: Scope
    op_id: int
    on_line: Callable[[str], None]
    raw_dir: Path
    http: AuthorizedHttpClient
    intel: IntelHttpClient

    @property
    def target(self) -> Target:
        """The authorized target."""
        return self.authorization.target

    def save_raw(self, text: str, extension: str, command: list[str] | None = None) -> Path:
        """Store raw tool output for evidence and record it on the operation."""
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        path = self.raw_dir / f"op_{self.op_id}.{extension}"
        path.write_text(text, encoding="utf-8", errors="replace")
        self.db.set_operation_command(self.op_id, " ".join(command or []), str(path))
        return path


@dataclass
class ActionOutput:
    """Structured result of a handler."""

    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    osint: list[dict[str, Any]] = field(default_factory=list)
    wifi: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)


Handler = Callable[[ActionContext, dict[str, Any]], Awaitable[ActionOutput]]


@dataclass(frozen=True)
class Action:
    """A registered capability of a module."""

    id: str
    module: str
    title: str
    intrusiveness: Intrusiveness
    target_kinds: frozenset[TargetKind]
    required_tools: tuple[str, ...]
    requires_root: bool
    handler: Handler
    params: tuple[str, ...] = ()
    description: str = ""
    any_tool: bool = False  # True: one of required_tools is enough
    consent: str = ""  # non-empty: always ask the operator to confirm this statement


@dataclass
class OperationResult:
    """What the UI receives after ``Engine.execute``."""

    op_id: int
    status: str  # "completed" | "failed" | "blocked"
    output: ActionOutput | None
    error: str | None


class Engine:
    """Registers actions and runs them under the security policy."""

    def __init__(
        self,
        settings: Settings,
        scope: Scope,
        db: Database,
        audit: AuditLogger,
        runner: SubprocessManager,
        root_check: Callable[[], bool] = is_root,
        resolver: Resolver = default_resolver,
        http: AuthorizedHttpClient | None = None,
        intel: IntelHttpClient | None = None,
    ) -> None:
        self.settings = settings
        self.scope = scope
        self.db = db
        self.audit = audit
        self.runner = runner
        self.http = http or AuthorizedHttpClient(audit)
        self.intel = intel or IntelHttpClient(audit)
        self._root_check = root_check
        self._resolver = resolver
        self._actions: dict[str, Action] = {}
        self._limiter = RateLimiter(settings.rate_limit_seconds)
        self.guard = ScopeGuard(scope, settings.mode, settings.operator, resolver)

    # -- registry ------------------------------------------------------------
    def register(self, action: Action) -> None:
        """Add an action; ids must be unique."""
        if action.id in self._actions:
            raise ValueError(f"duplicate action id {action.id}")
        self._actions[action.id] = action

    def actions(self, module: str | None = None) -> list[Action]:
        """Registered actions, optionally filtered by module."""
        return [a for a in self._actions.values() if module is None or a.module == module]

    def availability(self, action: Action) -> tuple[bool, str]:
        """Whether *action* can run right now, and why not."""
        missing = [t for t in action.required_tools if not self.runner.is_available(t)]
        if action.any_tool:
            if action.required_tools and len(missing) == len(action.required_tools):
                return False, "missing tools: " + " or ".join(action.required_tools)
        elif missing:
            return False, "missing tool: " + ", ".join(missing)
        if action.requires_root and not self._root_check():
            return False, "requires root (run with sudo)"
        return True, "ready"

    # -- settings ------------------------------------------------------------
    def set_mode(self, mode: Mode) -> None:
        """Switch passive/active mode (audited)."""
        previous = self.settings.mode
        self.settings.mode = mode
        self._rebuild_guard()
        self.audit.record(
            "settings_changed", operator=self.settings.operator,
            setting="mode", old=previous.value, new=mode.value,
        )

    def set_operator(self, operator: str) -> None:
        """Change the operator identity (audited)."""
        previous = self.settings.operator
        self.settings.operator = operator
        self._rebuild_guard()
        self.audit.record(
            "settings_changed", operator=operator, setting="operator", old=previous, new=operator
        )

    def reload_scope(self, scope: Scope) -> None:
        """Replace the scope (after the file was edited)."""
        self.scope = scope
        self._rebuild_guard()
        self.audit.record("settings_changed", operator=self.settings.operator, setting="scope")

    def _rebuild_guard(self) -> None:
        self.guard = ScopeGuard(self.scope, self.settings.mode, self.settings.operator, self._resolver)

    # -- execution -----------------------------------------------------------
    def _blocked(
        self, action: Action, target: str, event: str, reason: str
    ) -> OperationResult:
        op_id = self.db.create_operation(
            action.module, action.id, target[:200], self.settings.operator,
            action.intrusiveness.name.lower(),
        )
        self.db.finish_operation(op_id, "blocked", reason)
        self.audit.record(
            event, operator=self.settings.operator, action=action.id,
            target=target[:200], reason=reason, op_id=op_id,
        )
        return OperationResult(op_id, "blocked", None, reason)

    async def execute(
        self,
        action_id: str,
        raw_target: str,
        params: dict[str, Any] | None = None,
        *,
        confirm: Callable[[str], bool],
        on_line: Callable[[str], None] = lambda _line: None,
    ) -> OperationResult:
        """Run one action. Expected problems come back as a result, not an exception."""
        action = self._actions[action_id]
        params = dict(params or {})
        raw_target = raw_target if isinstance(raw_target, str) else str(raw_target)

        try:
            if action.target_kinds == frozenset({TargetKind.NONE}):
                target = LOCAL_TARGET
            elif action.target_kinds == frozenset({TargetKind.INTERFACE}):
                target = parse_interface_target(raw_target)
            elif action.target_kinds == frozenset({TargetKind.FILE}):
                target = parse_file_target(raw_target)
            else:
                target = parse_target(raw_target)
        except ValidationError as exc:
            return self._blocked(action, raw_target, "invalid_target", f"invalid target: {exc}")
        if target.kind not in action.target_kinds:
            kinds = ", ".join(sorted(k.value for k in action.target_kinds))
            return self._blocked(
                action, target.value, "invalid_target",
                f"{action.title} accepts only: {kinds}",
            )

        try:
            authorization = self.guard.authorize(target, action.intrusiveness)
        except ScopeViolation as exc:
            return self._blocked(action, target.value, "scope_blocked", str(exc))
        except ModeViolation as exc:
            return self._blocked(action, target.value, "mode_blocked", str(exc))

        available, reason = self.availability(action)
        if not available:
            return self._blocked(action, target.value, "precondition_failed", reason)

        if action.consent and not confirm(f"{action.title}: {action.consent}"):
            return self._blocked(
                action, target.value, "confirmation_declined", "operator declined the consent statement"
            )
        if action.intrusiveness > Intrusiveness.PASSIVE:
            prompt = (
                f"{action.title} [{action.intrusiveness.name}] against {target.value} "
                f"as operator {self.settings.operator}"
            )
            if not confirm(prompt):
                return self._blocked(
                    action, target.value, "confirmation_declined", "operator declined confirmation"
                )

        await self._limiter.wait()
        op_id = self.db.create_operation(
            action.module, action.id, target.value, self.settings.operator,
            action.intrusiveness.name.lower(),
        )
        self.audit.record(
            "scope_allowed", operator=self.settings.operator, action=action.id,
            target=target.value, resolved_ips=list(authorization.resolved_ips), op_id=op_id,
        )
        context = ActionContext(
            authorization=authorization, runner=self.runner, db=self.db, settings=self.settings,
            scope=self.scope, op_id=op_id, on_line=on_line, raw_dir=self.settings.logs_dir / "raw",
            http=self.http, intel=self.intel,
        )
        try:
            output = await action.handler(context, params)
            self.db.save_hosts(op_id, output.hosts)
            self.db.save_findings(op_id, output.findings)
            self.db.save_osint(op_id, output.osint)
            self.db.save_wifi(op_id, output.wifi)
            self.db.save_vulnerabilities(op_id, output.vulnerabilities)
        except Exception as exc:  # noqa: BLE001 - any handler failure fails the operation
            message = f"{type(exc).__name__}: {exc}"
            self.db.finish_operation(op_id, "failed", message)
            self.audit.record(
                "operation_failed", operator=self.settings.operator, action=action.id,
                target=target.value, error=message, op_id=op_id,
            )
            log.exception("operation %s failed", op_id)
            return OperationResult(op_id, "failed", None, message)
        self.db.finish_operation(op_id, "completed", summary=output.summary)
        return OperationResult(op_id, "completed", output, None)

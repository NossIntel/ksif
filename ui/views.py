"""Pure formatting helpers: data in, Rich renderables out. No logic, no I/O."""

from __future__ import annotations

from typing import Any

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.config import Scope, Settings
from core.models import Host
from ui.i18n import t as _


def _table(title: str, *columns: str) -> Table:
    table = Table(title=_(title), box=box.SIMPLE_HEAVY, title_style="ksif.title", header_style="ksif.dim",
                  expand=False)
    for column in columns:
        table.add_column(_(column), overflow="fold")
    return table


def _cell(value: Any, limit: int = 80) -> str:
    text = "" if value is None else str(value)
    return escape(text if len(text) <= limit else text[: limit - 1] + "…")


def severity_text(severity: str) -> Text:
    """Colour-coded severity label."""
    return Text(severity.upper(), style=f"sev.{severity if severity else 'unknown'}")


def header_panel(settings: Settings, scope: Scope) -> Panel:
    """Permanent status line: operator, mode, engagement, scope size."""
    mode_style = "ksif.passive" if settings.mode.value == "passive" else "ksif.active"
    scope_count = len(scope.ips) + len(scope.subnets) + len(scope.domains) + len(scope.interfaces) + len(scope.bssids)
    text = Text.assemble(
        (_("Operator") + " ", "ksif.dim"), (settings.operator, "bold"), ("   " + _("Mode") + " ", "ksif.dim"),
        (_(settings.mode.value).upper(), mode_style), ("   " + _("Engagement") + " ", "ksif.dim"),
        (scope.engagement or "-", "bold"), ("   " + _("scope entries") + " ", "ksif.dim"),
        (str(scope_count), "ksif.ok" if scope_count else "ksif.err"),
    )
    return Panel(text, box=box.ROUNDED, border_style="green")


def hosts_table(hosts: list[Host], title: str = "Hosts") -> Table:
    """One row per host."""
    table = _table(title, "Address", "Hostname", "MAC", "Vendor", "Type", "OS guess", "Open ports")
    for host in hosts:
        ports = ", ".join(str(p.number) for p in host.ports[:12]) + (" …" if len(host.ports) > 12 else "")
        os_guess = f"{host.os_guess} ({host.os_accuracy}%)" if host.os_guess else ""
        table.add_row(_cell(host.address), _cell(host.hostname), _cell(host.mac), _cell(host.vendor, 32),
                      _cell(host.device_type), _cell(os_guess, 36), _cell(ports))
    return table


def ports_table(hosts: list[Host]) -> Table:
    """One row per open port."""
    table = _table("Ports and services", "Host", "Port", "State", "Service", "Product", "Version")
    for host in hosts:
        for port in host.ports:
            table.add_row(_cell(host.address), f"{port.number}/{port.protocol}", _cell(port.state),
                          _cell(port.service), _cell(port.product, 40), _cell(port.version, 24))
    return table


def findings_table(findings: list[Any], title: str = "Findings") -> Table:
    """Findings (dataclass instances or DB rows)."""
    table = _table(title, "Severity", "Title", "Target", "Recommendation")
    for item in findings:
        get = item.get if isinstance(item, dict) else lambda key, _item=item: getattr(_item, key, "")
        table.add_row(severity_text(get("severity")), _cell(get("title"), 60), _cell(get("target"), 40),
                      _cell(get("recommendation"), 70))
    return table


def rows_table(title: str, rows: list[dict[str, Any]], columns: list[str] | None = None) -> Table:
    """Generic table for a list of dicts."""
    columns = columns or (list(rows[0]) if rows else [])
    table = _table(title, *[c.replace("_", " ").title() for c in columns])
    for row in rows:
        cells: list[Any] = []
        for column in columns:
            value = row.get(column)
            cells.append(severity_text(str(value)) if column == "severity" else _cell(value, 70))
        table.add_row(*cells)
    return table


def operations_table(operations: list[dict[str, Any]]) -> Table:
    """Operation history."""
    table = _table("Operation history", "#", "Started (UTC)", "Action", "Target", "Status", "Result")
    style = {"completed": "ksif.ok", "failed": "ksif.err", "blocked": "ksif.warn", "running": "ksif.dim"}
    for op in operations:
        table.add_row(str(op["id"]), _cell(op["started_at"]), _cell(op["action"]), _cell(op["target"], 40),
                      Text(op["status"], style=style.get(op["status"], "")),
                      _cell(op.get("summary") or op.get("error") or "", 60))
    return table


def data_panel(data: dict[str, Any]) -> Panel | None:
    """Compact view of the extra structured data an action returned."""
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"[ksif.key]{escape(key)}[/]")
            lines += [f"  {escape(str(k))}: {escape(_short(v))}" for k, v in list(value.items())[:40]]
        elif isinstance(value, list):
            lines.append(f"[ksif.key]{escape(key)}[/] ({len(value)})")
            lines += [f"  {escape(_short(v))}" for v in value[:40]]
            if len(value) > 40:
                lines.append(f"  … {len(value) - 40} more (see the report)")
        else:
            lines.append(f"[ksif.key]{escape(key)}[/]: {escape(_short(value))}")
    return Panel("\n".join(lines), title="Details", border_style="cyan", box=box.ROUNDED) if lines else None


def _short(value: Any, limit: int = 110) -> str:
    if isinstance(value, (list, tuple)):
        text = ", ".join(str(v) for v in value)
    else:
        text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"

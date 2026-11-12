"""Interactive terminal application. Presentation only: every operation goes
through ``Engine.execute`` and all security decisions are made there."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from core.config import load_scope, save_settings
from core.engine import Action, Engine, OperationResult
from core.logger import add_line_listener
from core.models import Intrusiveness, Mode, TargetKind
from integrations.registry import self_test_all
from modules.network_discovery.topology import subnet_map
from modules.reporting.builder import build_report
from modules.reporting.renderers import FORMATS, ReportFormatUnavailable, pdf_available, save_report
from ui import views
from ui.theme import ASCII_BANNER, BANNER, LEVEL_STYLE, TAGLINE

MAIN_MENU: list[tuple[str, str, str | None]] = [
    ("01", "Network Discovery", "network_discovery"),
    ("02", "OSINT Intelligence", "osint"),
    ("03", "Web Security Assessment", "web_security"),
    ("04", "Wi-Fi Security Audit", "wifi_audit"),
    ("05", "Password Security Lab", "password_lab"),
    ("06", "Vulnerability Intelligence", "vulnerability_intelligence"),
    ("07", "Asset Inventory", None),
    ("08", "Report Generator", None),
    ("09", "Configuration", None),
    ("10", "Exit", None),
]
PARAM_HINTS = {
    "ports": "Ports, e.g. 22,80,443 or 1-1024 (empty = default)",
    "interface": "Network interface (must be in scope), e.g. eth0",
    "rate": "Packets per second (empty = 100, hard cap 1000)",
    "duration": "Capture duration in seconds (empty = 30, max 300)",
    "wordlist": "Wordlist path (empty = tool default)",
    "format": "Hash format (empty = auto-detect)",
    "password": "Password to evaluate (input is not stored)",
    "min_length": "Minimum length required by your policy (empty = 12)",
    "query": "Product and version, e.g. nginx 1.18.0",
}


class Quit(Exception):
    """Raised to leave the application from any depth."""


class App:
    """The KSIF text user interface."""

    def __init__(
        self,
        engine: Engine,
        console: Console,
        ask: Callable[[str], str] | None = None,
        config_dir: Path | None = None,
    ) -> None:
        self.engine = engine
        self.console = console
        self._ask_raw = ask or console.input
        self.config_dir = config_dir

    # ------------------------------------------------------------ helpers
    def _ask(self, prompt: str) -> str:
        try:
            return self._ask_raw(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            raise Quit from None

    def _pause(self) -> None:
        self._ask("[ksif.dim]press Enter to continue[/] ")

    def _header(self) -> None:
        self.console.print(views.header_panel(self.engine.settings, self.engine.scope))

    def _banner(self) -> None:
        encoding = (self.console.encoding or "").lower()
        art = BANNER if "utf" in encoding else ASCII_BANNER
        self.console.print(Text(art, style="ksif.banner"))
        self.console.print(f"[ksif.title]{TAGLINE}[/]  [ksif.dim]authorized use only[/]\n")

    # ------------------------------------------------------------ main loop
    def run(self) -> int:
        """Run until the operator exits. Returns a process exit code."""
        self._banner()
        try:
            while True:
                self._header()
                menu = Table(box=box.ROUNDED, show_header=False, border_style="green", title="Main menu",
                             title_style="ksif.title")
                for number, title, module in MAIN_MENU:
                    note = ""
                    if module is not None and not self.engine.actions(module):
                        note = "[ksif.dim]not yet available[/]"
                    menu.add_row(f"[ksif.key]\\[{number}][/]", title, note)
                self.console.print(menu)
                choice = self._ask("[ksif.key]ksif>[/] ").lstrip("0") or "0"
                if choice == "10":
                    break
                entry = next((e for e in MAIN_MENU if e[0].lstrip("0") == choice), None)
                if entry is None:
                    self.console.print("[ksif.warn]Unknown option.[/]")
                elif entry[2] is not None:
                    self._module_menu(entry[1], entry[2])
                elif entry[0] == "07":
                    self._inventory_menu()
                elif entry[0] == "08":
                    self._report_menu()
                elif entry[0] == "09":
                    self._config_menu()
        except Quit:
            pass
        self.console.print("[ksif.dim]Session closed.[/]")
        return 0

    # ------------------------------------------------------------ modules
    def _module_menu(self, title: str, module: str) -> None:
        actions = self.engine.actions(module)
        if not actions:
            self.console.print(Panel(f"{title}: not yet available in this version.", border_style="yellow"))
            return
        while True:
            table = Table(title=title, box=box.ROUNDED, border_style="cyan", title_style="ksif.title")
            for column in ("#", "Action", "Level", "Status", "Description"):
                table.add_column(column, overflow="fold")
            for index, action in enumerate(actions, start=1):
                ready, reason = self.engine.availability(action)
                table.add_row(
                    f"[ksif.key]\\[{index:02d}][/]", action.title,
                    Text(action.intrusiveness.name.lower(), style=LEVEL_STYLE[action.intrusiveness]),
                    Text(reason, style="ksif.ok" if ready else "ksif.warn"), action.description,
                )
            table.add_row("[ksif.key]\\[00][/]", "Back", "", "", "")
            self.console.print(table)
            choice = self._ask(f"[ksif.key]{module}>[/] ")
            if choice in ("0", "00", ""):
                return
            if not choice.isdigit() or not 1 <= int(choice) <= len(actions):
                self.console.print("[ksif.warn]Unknown option.[/]")
                continue
            self._run_action(actions[int(choice) - 1])
            self._pause()

    def _target_prompt(self, action: Action) -> str | None:
        kinds = action.target_kinds
        if kinds == frozenset({TargetKind.NONE}):
            return ""
        if kinds == frozenset({TargetKind.INTERFACE}):
            label = "Interface (must be listed in scope.yaml)"
        elif kinds == frozenset({TargetKind.FILE}):
            label = "File path"
        else:
            label = "Target (" + ", ".join(sorted(k.value for k in kinds)) + ")"
        value = self._ask(f"{label}: ")
        return value or None

    def _confirm(self, raw_target: str, live_box: list[Live | None]) -> Callable[[str], bool]:
        def confirm(prompt: str) -> bool:
            live = live_box[0]
            if live is not None:
                live.stop()
            try:
                self.console.print(Panel(escape(prompt), title="Confirmation required", border_style="yellow"))
                if f"[{Intrusiveness.INTRUSIVE.name}]" in prompt:
                    typed = self._ask("Intrusive action. Type the target again to confirm: ")
                    return bool(typed) and typed.lower() == raw_target.strip().lower()
                return self._ask("Proceed? [y/N]: ").lower() in ("y", "yes")
            finally:
                if live is not None:
                    live.start()

        return confirm

    def _run_action(self, action: Action) -> OperationResult | None:
        target = self._target_prompt(action)
        if target is None:
            self.console.print("[ksif.warn]No target given; nothing was run.[/]")
            return None
        params: dict[str, Any] = {}
        for name in action.params:
            value = self._ask(f"{PARAM_HINTS.get(name, name)}: ")
            if value:
                params[name] = value

        tail: deque[str] = deque(maxlen=8)
        progress = Progress(
            SpinnerColumn(style="green"), TextColumn("[ksif.title]{task.description}"),
            BarColumn(bar_width=24, pulse_style="green"), TimeElapsedColumn(), console=self.console,
        )
        progress.add_task(f"{action.title} → {target or 'local data'}", total=None)

        def render() -> Group:
            body = "\n".join(escape(line[:160]) for line in tail) or "[ksif.dim]waiting for output…[/]"
            return Group(progress, Panel(body, title="Live log", border_style="grey37", box=box.ROUNDED))

        live_box: list[Live | None] = [None]

        def on_line(line: str) -> None:
            tail.append(line)
            if live_box[0] is not None:
                live_box[0].update(render())

        remove_listener = add_line_listener(on_line)
        try:
            with Live(render(), console=self.console, refresh_per_second=8, transient=True) as live:
                live_box[0] = live
                result = asyncio.run(
                    self.engine.execute(action.id, target, params,
                                        confirm=self._confirm(target, live_box), on_line=on_line)
                )
        finally:
            live_box[0] = None
            remove_listener()
        self._show_result(action, result)
        return result

    def _show_result(self, action: Action, result: OperationResult) -> None:
        if result.status == "blocked":
            self.console.print(Panel(f"[ksif.warn]BLOCKED[/] {escape(result.error or '')}",
                                     title=f"Operation #{result.op_id}", border_style="yellow"))
            return
        if result.status == "failed":
            op = self.engine.db.get_operation(result.op_id) or {}
            raw = op.get("raw_output_path")
            hint = f"\nRaw tool output kept at: {escape(raw)}" if raw else ""
            self.console.print(Panel(f"[ksif.err]FAILED[/] {escape(result.error or '')}{hint}",
                                     title=f"Operation #{result.op_id}", border_style="red"))
            return
        output = result.output
        assert output is not None
        self.console.print(Panel(f"[ksif.ok]COMPLETED[/] {escape(output.summary)}",
                                 title=f"Operation #{result.op_id} · {action.title}", border_style="green"))
        if output.hosts:
            self.console.print(views.hosts_table(output.hosts))
            if any(host.ports for host in output.hosts):
                self.console.print(views.ports_table(output.hosts))
        if output.findings:
            self.console.print(views.findings_table(output.findings))
        panel = views.data_panel(output.data)
        if panel is not None:
            self.console.print(panel)

    # ------------------------------------------------------------ inventory
    def _inventory_menu(self) -> None:
        db = self.engine.db
        options = [
            ("1", "Hosts"), ("2", "Ports and services"), ("3", "Subnet map"), ("4", "Findings"),
            ("5", "Vulnerabilities"), ("6", "OSINT records"), ("7", "Wi-Fi networks"),
            ("8", "Operation history"), ("0", "Back"),
        ]
        while True:
            self._options("Asset Inventory", options)
            choice = self._ask("[ksif.key]inventory>[/] ")
            if choice in ("0", ""):
                return
            hosts = db.list_hosts()
            if choice == "1":
                self._print_or_empty(views.hosts_table(hosts, f"Hosts ({len(hosts)})"), hosts)
            elif choice == "2":
                self._print_or_empty(views.ports_table(hosts), [p for h in hosts for p in h.ports])
            elif choice == "3":
                mapping = subnet_map(hosts)
                rows = [{"subnet": net, "hosts": len(addrs), "addresses": ", ".join(addrs)}
                        for net, addrs in mapping.items()]
                self._print_or_empty(views.rows_table("Subnet map", rows), rows)
            elif choice == "4":
                rows = db.list_findings()
                self._print_or_empty(views.findings_table(rows, f"Findings ({len(rows)})"), rows)
            elif choice == "5":
                rows = db.list_rows("vulnerabilities", None, "priority DESC, id")
                cols = ["cve_id", "severity", "cvss", "epss", "kev", "host", "product", "version", "priority"]
                self._print_or_empty(views.rows_table("Vulnerabilities (by priority)", rows, cols), rows)
            elif choice == "6":
                rows = db.list_rows("osint_records", None, "kind, name")
                self._print_or_empty(views.rows_table("OSINT records", rows, ["kind", "name", "value", "source"]), rows)
            elif choice == "7":
                rows = db.list_rows("wifi_networks", None, "owned DESC, ssid")
                cols = ["ssid", "bssid", "channel", "band", "security", "signal", "owned"]
                self._print_or_empty(views.rows_table("Wi-Fi networks", rows, cols), rows)
            elif choice == "8":
                rows = db.list_operations(40)
                self._print_or_empty(views.operations_table(rows), rows)
            else:
                self.console.print("[ksif.warn]Unknown option.[/]")

    def _print_or_empty(self, renderable: Any, rows: list[Any]) -> None:
        if rows:
            self.console.print(renderable)
        else:
            self.console.print("[ksif.dim]Nothing stored yet.[/]")

    def _options(self, title: str, options: list[tuple[str, str]]) -> None:
        table = Table(title=title, box=box.ROUNDED, show_header=False, border_style="cyan",
                      title_style="ksif.title")
        for key, label in options:
            table.add_row(f"[ksif.key]\\[{key}][/]", label)
        self.console.print(table)

    # ------------------------------------------------------------ reports
    def _report_menu(self) -> None:
        self._options("Report Generator", [("1", "Report on everything stored"),
                                           ("2", "Report on one operation"), ("0", "Back")])
        choice = self._ask("[ksif.key]report>[/] ")
        op_ids: list[int] | None = None
        if choice == "2":
            self.console.print(views.operations_table(self.engine.db.list_operations(20)))
            raw = self._ask("Operation #: ")
            if not raw.isdigit() or self.engine.db.get_operation(int(raw)) is None:
                self.console.print("[ksif.warn]No such operation.[/]")
                return
            op_ids = [int(raw)]
        elif choice != "1":
            return
        labels = ", ".join(f"{f}{'' if f != 'pdf' or pdf_available() else ' (unavailable)'}" for f in FORMATS)
        fmt = self._ask(f"Format [{labels}]: ").lower() or "html"
        if fmt == "md":
            fmt = "markdown"
        if fmt not in FORMATS:
            self.console.print("[ksif.warn]Unknown format.[/]")
            return
        report = build_report(self.engine.db, self.engine.scope, self.engine.settings, op_ids)
        try:
            path = save_report(self.engine.db, self.engine.settings, report, fmt)
        except ReportFormatUnavailable as exc:
            self.console.print(f"[ksif.warn]{escape(str(exc))}[/]")
            return
        except OSError as exc:
            self.console.print(f"[ksif.err]Could not write the report: {escape(str(exc))}[/]")
            return
        self.console.print(Panel(f"[ksif.ok]Report written[/]\n{escape(str(path))}", border_style="green"))

    # ------------------------------------------------------------ configuration
    def _config_menu(self) -> None:
        while True:
            self._show_config()
            self._options("Configuration", [
                ("1", "Switch passive / active mode"), ("2", "Change operator"),
                ("3", "Reload scope.yaml"), ("4", "Check external tools (runs each tool)"),
                ("5", "Show audit log"), ("0", "Back"),
            ])
            choice = self._ask("[ksif.key]config>[/] ")
            if choice in ("0", ""):
                return
            if choice == "1":
                self._toggle_mode()
            elif choice == "2":
                name = self._ask("Operator name: ")
                if name and len(name) <= 64 and name.isprintable():
                    self.engine.set_operator(name)
                    self._save_settings()
                else:
                    self.console.print("[ksif.warn]Operator unchanged.[/]")
            elif choice == "3":
                if self.config_dir is None:
                    self.console.print("[ksif.warn]No configuration directory.[/]")
                else:
                    self.engine.reload_scope(load_scope(self.config_dir / "scope.yaml"))
                    self.console.print("[ksif.ok]Scope reloaded.[/]")
            elif choice == "4":
                rows = asyncio.run(self_test_all(self.engine.runner))
                table = Table(title="External tools", box=box.SIMPLE_HEAVY, title_style="ksif.title")
                for column in ("Module", "Tool", "Status", "Version / reason"):
                    table.add_column(column)
                for row in rows:
                    table.add_row(str(row["module"]), str(row["tool"]),
                                  Text("ok" if row["ok"] else "missing", style="ksif.ok" if row["ok"] else "ksif.warn"),
                                  escape(str(row["detail"])))
                self.console.print(table)
            elif choice == "5":
                rows = [{"ts": r["ts"], "operator": r["operator"], "event": r["event"],
                         "detail": ", ".join(f"{k}={v}" for k, v in r["detail"].items())}
                        for r in self.engine.db.list_audit(25)]
                self._print_or_empty(views.rows_table("Audit log (latest first)", rows), rows)
            else:
                self.console.print("[ksif.warn]Unknown option.[/]")

    def _show_config(self) -> None:
        settings, scope = self.engine.settings, self.engine.scope
        table = Table(box=box.SIMPLE, show_header=False)
        rows = [
            ("Operator", settings.operator), ("Mode", settings.mode.value),
            ("Rate limit", f"{settings.rate_limit_seconds:g}s between operations"),
            ("Timeout", f"{settings.default_timeout_seconds}s"), ("Database", str(settings.database_path)),
            ("Logs", str(settings.logs_dir)), ("Reports", str(settings.reports_dir)),
            ("Engagement", scope.engagement or "(not set)"), ("Scope IPs", ", ".join(scope.ips) or "-"),
            ("Scope subnets", ", ".join(scope.subnets) or "-"), ("Scope domains", ", ".join(scope.domains) or "-"),
            ("Scope interfaces", ", ".join(scope.interfaces) or "-"), ("Own BSSIDs", ", ".join(scope.bssids) or "-"),
        ]
        for key, value in rows:
            table.add_row(f"[ksif.dim]{key}[/]", escape(value))
        self.console.print(Panel(table, title="Current configuration", border_style="cyan"))
        if scope.is_empty:
            self.console.print("[ksif.warn]Scope is empty: no active operation can run. "
                               "Edit config/scope.yaml and reload.[/]")
        for error in scope.errors:
            self.console.print(f"[ksif.err]scope problem:[/] {escape(error)}")

    def _toggle_mode(self) -> None:
        if self.engine.settings.mode is Mode.PASSIVE:
            self.console.print(Panel(
                "Active mode lets KSIF send traffic to the targets in your scope.\n"
                "Only continue if you own these systems or hold written authorization.",
                title="Switch to ACTIVE mode", border_style="yellow"))
            if self._ask("I am authorized to assess every target in scope [y/N]: ").lower() not in ("y", "yes"):
                self.console.print("[ksif.dim]Mode unchanged.[/]")
                return
            self.engine.set_mode(Mode.ACTIVE)
        else:
            self.engine.set_mode(Mode.PASSIVE)
        self._save_settings()
        self.console.print(f"[ksif.ok]Mode is now {self.engine.settings.mode.value}.[/]")

    def _save_settings(self) -> None:
        if self.config_dir is None:
            return
        try:
            save_settings(self.engine.settings, self.config_dir / "settings.yaml", self.config_dir.parent)
        except OSError as exc:
            self.console.print(f"[ksif.warn]Could not save settings: {escape(str(exc))}[/]")

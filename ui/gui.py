"""KSIF graphical interface (Tkinter).

A desktop front end over the same ``Engine`` as the terminal UI: every
operation goes through ``Engine.execute`` and all security decisions (scope,
mode, confirmation) are made there. The GUI runs one action at a time in a
worker thread and streams its log back to the window.

Tkinter ships with Python, so this works from a PyInstaller build with no extra
dependency. External tools (nmap, nuclei, ...) are detected at runtime; on a
system without them, the matching actions show as unavailable.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

from core.config import load_scope, save_settings
from core.engine import Action, Engine, OperationResult
from core.logger import add_line_listener
from core.models import Intrusiveness, Mode, TargetKind
from integrations.registry import self_test_all
from modules.reporting.builder import build_report
from modules.reporting.renderers import FORMATS, ReportFormatUnavailable, save_report
from ui import i18n
from ui.i18n import t as _

BG = "#0d1117"
FG = "#c9d1d9"
ACCENT = "#238636"
PANEL = "#161b22"
WARN = "#d29922"
ERR = "#f85149"
MODULES = [
    ("01  Network Discovery", "network_discovery"),
    ("02  OSINT Intelligence", "osint"),
    ("03  Web Security", "web_security"),
    ("04  Wi-Fi Audit", "wifi_audit"),
    ("05  Password Lab", "password_lab"),
    ("06  Vulnerability Intel", "vulnerability_intelligence"),
]
LEVEL_COLOR = {Intrusiveness.PASSIVE: "#58a6ff", Intrusiveness.ACTIVE: WARN, Intrusiveness.INTRUSIVE: ERR}


class _Confirm:
    """Bridge a worker-thread confirm() to a main-thread dialog."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root

    def ask(self, prompt: str) -> bool:
        event = threading.Event()
        box: dict[str, bool] = {}

        def show() -> None:
            box["value"] = messagebox.askyesno("KSIF — confirmation required", prompt)
            event.set()

        self.root.after(0, show)
        event.wait()
        return box.get("value", False)


class KsifGui:
    """The main window."""

    def __init__(self, root: tk.Tk, engine: Engine, config_dir: Path) -> None:
        self.root = root
        self.engine = engine
        self.config_dir = config_dir
        self.log_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.current_action: Action | None = None
        self.param_vars: dict[str, tk.StringVar] = {}
        self.running = False
        self._confirm = _Confirm(root)
        i18n.set_language(getattr(engine.settings, "language", "pt"))

        root.title("KSIF — Kali Security Intelligence Framework")
        root.geometry("1100x720")
        root.configure(bg=BG)
        self._style()
        self._build()
        add_line_listener(lambda line: self.log_queue.put(("log", line)))
        self.root.after(80, self._drain)
        self._refresh_header()
        self._select_module("network_discovery")

    # ------------------------------------------------------------ styling
    def _style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL, bordercolor=PANEL)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("Head.TLabel", background=PANEL, foreground="#58d68d", font=("Segoe UI", 10, "bold"))
        style.configure("TButton", background=ACCENT, foreground="white", borderwidth=0, padding=6)
        style.map("TButton", background=[("active", "#2ea043"), ("disabled", "#30363d")])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, borderwidth=0)
        style.configure("Treeview.Heading", background="#21262d", foreground=FG)
        style.map("Treeview", background=[("selected", ACCENT)])
        style.configure("TEntry", fieldbackground="#0b0f14", foreground=FG)
        style.configure("TCombobox", fieldbackground="#0b0f14", foreground=FG)

    # ------------------------------------------------------------ layout
    def _build(self) -> None:
        header = ttk.Frame(self.root, style="Panel.TFrame", padding=8)
        header.pack(fill="x")
        self.header_label = ttk.Label(header, style="Head.TLabel", text="")
        self.header_label.pack(side="left")
        ttk.Button(header, text=_("Toggle mode"), command=self._toggle_mode).pack(side="right", padx=4)
        ttk.Button(header, text=_("Language"), command=self._toggle_language).pack(side="right", padx=4)
        ttk.Button(header, text=_("Tools"), command=self._tool_check).pack(side="right", padx=4)
        ttk.Button(header, text=_("Reload scope"), command=self._reload_scope).pack(side="right", padx=4)
        ttk.Button(header, text=_("Report"), command=self._report).pack(side="right", padx=4)
        ttk.Button(header, text=_("Inventory"), command=self._inventory).pack(side="right", padx=4)

        body = ttk.Frame(self.root, padding=6)
        body.pack(fill="both", expand=True)

        left = ttk.Frame(body)
        left.pack(side="left", fill="y", padx=(0, 6))
        ttk.Label(left, text=_("Modules")).pack(anchor="w")
        self.module_list = tk.Listbox(left, bg=PANEL, fg=FG, selectbackground=ACCENT, width=26,
                                      height=8, borderwidth=0, highlightthickness=0, activestyle="none")
        for label, key in MODULES:
            number = label.split()[0]
            self.module_list.insert("end", f"{number}  {_(label.split('  ', 1)[1])}")
        self.module_list.pack(fill="y")
        self.module_list.bind("<<ListboxSelect>>", self._on_module)

        mid = ttk.Frame(body)
        mid.pack(side="left", fill="both", expand=True, padx=(0, 6))
        ttk.Label(mid, text=_("Actions")).pack(anchor="w")
        self.action_tree = ttk.Treeview(mid, columns=("level", "status"), show="tree headings", height=9)
        self.action_tree.heading("#0", text=_("Action"))
        self.action_tree.heading("level", text=_("Level"))
        self.action_tree.heading("status", text=_("Status"))
        self.action_tree.column("#0", width=260)
        self.action_tree.column("level", width=80, anchor="center")
        self.action_tree.column("status", width=150)
        self.action_tree.pack(fill="x")
        self.action_tree.bind("<<TreeviewSelect>>", self._on_action)

        form = ttk.Frame(mid, style="Panel.TFrame", padding=8)
        form.pack(fill="x", pady=6)
        self.form = form
        self.desc_label = ttk.Label(form, text=_("Select an action"), wraplength=520)
        self.desc_label.pack(anchor="w")
        self.target_row = ttk.Frame(form, style="Panel.TFrame")
        self.target_row.pack(fill="x", pady=4)
        self.target_label = ttk.Label(self.target_row, text=_("Target"), width=12)
        self.target_label.pack(side="left")
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(self.target_row, textvariable=self.target_var, width=48)
        self.target_entry.pack(side="left", fill="x", expand=True)
        self.browse_btn = ttk.Button(self.target_row, text=_("Browse"), command=self._browse)
        self.params_frame = ttk.Frame(form, style="Panel.TFrame")
        self.params_frame.pack(fill="x")
        ttk.Label(form, text=_("How to use & exact command"), style="Head.TLabel").pack(anchor="w", pady=(6, 0))
        self.howto = scrolledtext.ScrolledText(form, bg="#0b0f14", fg="#8b949e", height=7,
                                               borderwidth=0, font=("Consolas", 9), wrap="word")
        self.howto.pack(fill="x")
        self.howto.tag_config("cmd", foreground="#58d68d")
        self.howto.tag_config("warn", foreground=WARN)
        btn_row = ttk.Frame(form, style="Panel.TFrame")
        btn_row.pack(fill="x", pady=4)
        ttk.Button(btn_row, text=_("Preview command"), command=lambda: self._update_howto(True)).pack(side="left")
        self.run_btn = ttk.Button(btn_row, text=_("Run"), command=self._run)
        self.run_btn.pack(side="right")

        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True)
        ttk.Label(right, text=_("Live log")).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(right, bg="#0b0f14", fg="#8b949e", height=12,
                                             insertbackground=FG, borderwidth=0, font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)
        ttk.Label(right, text=_("Results")).pack(anchor="w")
        self.results = scrolledtext.ScrolledText(right, bg=PANEL, fg=FG, height=14,
                                                 borderwidth=0, font=("Consolas", 9))
        self.results.pack(fill="both", expand=True)
        self._tag_colors(self.results)

        self.status = ttk.Label(self.root, text=_("Ready"), anchor="w")
        self.status.pack(fill="x", side="bottom")

    def _tag_colors(self, widget: scrolledtext.ScrolledText) -> None:
        widget.tag_config("ok", foreground="#3fb950")
        widget.tag_config("warn", foreground=WARN)
        widget.tag_config("err", foreground=ERR)
        widget.tag_config("head", foreground="#58d68d", font=("Consolas", 10, "bold"))

    # ------------------------------------------------------------ data flow
    def _refresh_header(self) -> None:
        s, sc = self.engine.settings, self.engine.scope
        count = len(sc.ips) + len(sc.subnets) + len(sc.domains) + len(sc.interfaces) + len(sc.bssids)
        self.header_label.configure(
            text=f"{_('Operator')} {s.operator}    {_('Mode')} {_(s.mode.value).upper()}    "
                 f"{_('Engagement')} {sc.engagement or '-'}    {_('scope entries')} {count}")

    def _on_module(self, _event: object) -> None:
        selection = self.module_list.curselection()
        if selection:
            self._select_module(MODULES[selection[0]][1])

    def _select_module(self, module: str) -> None:
        self.module = module
        self.action_tree.delete(*self.action_tree.get_children())
        for action in self.engine.actions(module):
            ready, reason = self.engine.availability(action)
            self.action_tree.insert("", "end", iid=action.id, text=i18n.action_title(action),
                                    values=(_(action.intrusiveness.name.lower()),
                                            _("ready") if ready else _(reason)))
        self.actions_by_id = {a.id: a for a in self.engine.actions(module)}

    def _on_action(self, _event: object) -> None:
        selection = self.action_tree.selection()
        if not selection:
            return
        action = self.actions_by_id.get(selection[0])
        if not action:
            return
        self.current_action = action
        self.desc_label.configure(text=f"{i18n.action_title(action)} — {i18n.action_description(action)}\n"
                                       f"{_('intrusiveness:')} {_(action.intrusiveness.name.lower())}"
                                       + (f"  ·  {_('consent required')}" if action.consent else ""))
        kinds = action.target_kinds
        if kinds == frozenset({TargetKind.NONE}):
            self.target_row.pack_forget()
        else:
            self.target_row.pack(fill="x", pady=4, after=self.desc_label)
            if kinds == frozenset({TargetKind.INTERFACE}):
                self.target_label.configure(text=_("Interface"))
            elif kinds == frozenset({TargetKind.FILE}):
                self.target_label.configure(text=_("File"))
            else:
                self.target_label.configure(text=_("Target"))
            if kinds == frozenset({TargetKind.FILE}):
                self.browse_btn.pack(side="left", padx=4)
            else:
                self.browse_btn.pack_forget()
        for widget in self.params_frame.winfo_children():
            widget.destroy()
        self.param_vars = {}
        for name in action.params:
            row = ttk.Frame(self.params_frame, style="Panel.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=name, width=12).pack(side="left")
            var = tk.StringVar()
            show = "*" if name == "password" else ""
            ttk.Entry(row, textvariable=var, show=show, width=40).pack(side="left", fill="x", expand=True)
            self.param_vars[name] = var
        self._update_howto(False)

    def _update_howto(self, use_inputs: bool) -> None:
        """Fill the how-to/command box, from the typed target/params or an example."""
        if not self.current_action:
            return
        target = self.target_var.get().strip() if use_inputs else ""
        params = {n: v.get().strip() for n, v in self.param_vars.items()} if use_inputs else {}
        info = self.engine.describe(self.current_action.id, target, params)
        usage = i18n.action_usage(self.current_action)
        self.howto.delete("1.0", "end")
        if usage:
            self.howto.insert("end", usage + "\n\n")
        if info["requires_root"]:
            self.howto.insert("end", _("needs root (run with sudo)") + "\n", "warn")
        label = _("command that will run:") if use_inputs and target else _("example command:")
        self.howto.insert("end", label + "\n")
        for cmd in info["commands"]:
            self.howto.insert("end", "  " + cmd + "\n", "cmd")

    def _browse(self) -> None:
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.target_var.set(path)

    # ------------------------------------------------------------ run
    def _run(self) -> None:
        if self.running or not self.current_action:
            return
        action = self.current_action
        ready, reason = self.engine.availability(action)
        if not ready:
            messagebox.showwarning("KSIF", f"{_('Cannot run:')} {_(reason)}")
            return
        target = self.target_var.get().strip() if action.target_kinds != frozenset({TargetKind.NONE}) else ""
        params = {name: var.get().strip() for name, var in self.param_vars.items() if var.get().strip()}
        self.running = True
        self.run_btn.configure(state="disabled")
        self.status.configure(text=f"{_('Running ')}{i18n.action_title(action)}…")
        self.log.delete("1.0", "end")
        info = self.engine.describe(action.id, target, params)
        for cmd in info["commands"]:
            self.log.insert("end", "$ " + cmd + "\n")
        self.log.insert("end", "\n")
        threading.Thread(target=self._worker, args=(action, target, params), daemon=True).start()

    def _worker(self, action: Action, target: str, params: dict[str, Any]) -> None:
        def on_line(line: str) -> None:
            self.log_queue.put(("log", line))
        try:
            result = asyncio.run(self.engine.execute(action.id, target, params,
                                                     confirm=self._confirm.ask, on_line=on_line))
        except Exception as exc:  # noqa: BLE001 - surface any unexpected failure
            self.log_queue.put(("done", ("error", action, str(exc))))
            return
        self.log_queue.put(("done", ("result", action, result)))

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.log_queue.get_nowait()
                if kind == "log":
                    self.log.insert("end", str(payload) + "\n")
                    self.log.see("end")
                elif kind == "done":
                    self._finish(*payload)
        except queue.Empty:
            pass
        self.root.after(80, self._drain)

    def _finish(self, kind: str, action: Action, payload: Any) -> None:
        self.running = False
        self.run_btn.configure(state="normal")
        if kind == "error":
            self.status.configure(text=_("Error"))
            self._write(f"\n{_('Error')}: {payload}\n", "err")
            return
        result: OperationResult = payload
        self.status.configure(text=f"{_('Operation #')}{result.op_id}: {result.status}")
        if result.status == "blocked":
            self._write(f"\n[{_('BLOCKED')}] {_(result.error or '')}\n", "warn")
        elif result.status == "failed":
            self._write(f"\n[{_('FAILED')}] {_(result.error or '')}\n", "err")
        else:
            self._render_result(action, result)
        self._refresh_header()

    def _render_result(self, action: Action, result: OperationResult) -> None:
        out = result.output
        self._write(f"\n[{_('COMPLETED')}] {i18n.action_title(action)} — {out.summary}\n", "ok")
        if out.hosts:
            self._write(f"\n{_('Hosts')} ({len(out.hosts)}):\n", "head")
            for host in out.hosts:
                ports = ",".join(str(p.number) for p in host.ports[:16])
                self._write(f"  {host.address:<20} {host.device_type or '':<14} "
                            f"{(host.vendor or '')[:24]:<24} {ports}\n")
        if out.findings:
            self._write(f"\n{_('Findings')} ({len(out.findings)}):\n", "head")
            for finding in out.findings:
                tag = {"critical": "err", "high": "err", "medium": "warn"}.get(finding.severity, "")
                self._write(f"  [{finding.severity.upper():<8}] {finding.title} ({finding.target})\n", tag)
        if out.vulnerabilities:
            self._write(f"\n{_('Vulnerabilities')} ({len(out.vulnerabilities)}):\n", "head")
            for vuln in sorted(out.vulnerabilities, key=lambda v: -v.get("priority", 0))[:25]:
                kev = " [KEV]" if vuln.get("kev") else ""
                self._write(f"  {vuln['cve_id']:<18} prio {vuln.get('priority')}  "
                            f"{vuln.get('product', '')}{kev}\n")
        if out.osint:
            self._write(f"\n{_('OSINT records')}: {len(out.osint)}\n", "head")
        if out.wifi:
            self._write(f"\n{_('Wi-Fi networks')} ({len(out.wifi)}):\n", "head")
            for net in out.wifi[:30]:
                self._write(f"  {net['bssid']}  {net.get('ssid') or '<hidden>':<24} "
                            f"{net.get('security'):<12} {'OWNED' if net.get('owned') else ''}\n")
        if out.data:
            self._write(f"\nDetails: {_short_dict(out.data)}\n")

    def _write(self, text: str, tag: str = "") -> None:
        self.results.insert("end", text, tag)
        self.results.see("end")

    # ------------------------------------------------------------ menu actions
    def _toggle_mode(self) -> None:
        if self.engine.settings.mode is Mode.PASSIVE:
            if not messagebox.askyesno("KSIF", _("Switch to ACTIVE mode?") + "\n\n"
                                       + _("Active mode sends traffic to targets in your scope. "
                                           "Continue only if you are authorized.")):
                return
            self.engine.set_mode(Mode.ACTIVE)
        else:
            self.engine.set_mode(Mode.PASSIVE)
        self._save_settings()
        self._refresh_header()
        self._select_module(self.module)

    def _toggle_language(self) -> None:
        new = "en" if i18n.language() == "pt" else "pt"
        self.engine.settings.language = i18n.set_language(new)
        self._save_settings()
        messagebox.showinfo("KSIF", {"pt": "Idioma: português. Reabra para traduzir tudo.",
                                     "en": "Language: English. Reopen to translate everything."}[new])
        self._refresh_header()
        self._select_module(self.module)
        if self.current_action:
            self._update_howto(False)

    def _reload_scope(self) -> None:
        self.engine.reload_scope(load_scope(self.config_dir / "scope.yaml"))
        self._refresh_header()
        self._select_module(self.module)
        errors = self.engine.scope.errors
        messagebox.showinfo("KSIF", _("Scope reloaded.")
                            + ("\n\n" + _("Problems:") + "\n" + "\n".join(errors) if errors else ""))

    def _tool_check(self) -> None:
        self.status.configure(text=_("Checking tools") + "…")

        def work() -> None:
            rows = asyncio.run(self_test_all(self.engine.runner))
            self.log_queue.put(("tools", rows))
        threading.Thread(target=work, daemon=True).start()
        self.root.after(120, self._poll_tools)

    def _poll_tools(self) -> None:
        try:
            kind, rows = self.log_queue.get_nowait()
        except queue.Empty:
            self.root.after(150, self._poll_tools)
            return
        if kind != "tools":
            return
        lines = [f"{'OK ' if r['ok'] else 'MISSING'}  {r['tool']:<16} {r['detail']}" for r in rows]
        messagebox.showinfo(_("External tools"), "\n".join(lines))
        self.status.configure(text=_("Ready"))

    def _report(self) -> None:
        fmt = _ask_choice(self.root, _("Report format"), FORMATS, "html")
        if not fmt:
            return
        report = build_report(self.engine.db, self.engine.scope, self.engine.settings)
        try:
            path = save_report(self.engine.db, self.engine.settings, report, fmt)
        except (ReportFormatUnavailable, OSError, ValueError) as exc:
            messagebox.showwarning("KSIF", str(exc))
            return
        messagebox.showinfo("KSIF", f"{_('Report written:')}\n{path}")

    def _inventory(self) -> None:
        hosts = self.engine.db.list_hosts()
        vulns = self.engine.db.list_rows("vulnerabilities", None, "priority DESC")
        osint = self.engine.db.list_rows("osint_records")
        wifi = self.engine.db.list_rows("wifi_networks")
        self.results.delete("1.0", "end")
        self._write(_("Asset Inventory") + "\n", "head")
        self._write(f"  {_('Hosts')}: {len(hosts)}   {_('Vulnerabilities')}: {len(vulns)}   "
                    f"{_('OSINT records')}: {len(osint)}   {_('Wi-Fi networks')}: {len(wifi)}\n\n")
        for host in hosts:
            self._write(f"  {host.address:<20} {host.device_type or '':<14} "
                        f"{len(host.ports)} port(s)\n")
        self.status.configure(text=_("Inventory shown"))

    def _save_settings(self) -> None:
        try:
            save_settings(self.engine.settings, self.config_dir / "settings.yaml", self.config_dir.parent)
        except OSError:
            pass


def _short_dict(data: dict[str, Any], limit: int = 400) -> str:
    text = ", ".join(f"{k}={v}" for k, v in data.items())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _ask_choice(root: tk.Tk, title: str, options: tuple[str, ...], default: str) -> str | None:
    win = tk.Toplevel(root)
    win.title(title)
    win.configure(bg=BG)
    win.transient(root)
    win.grab_set()
    ttk.Label(win, text=title).pack(padx=12, pady=8)
    var = tk.StringVar(value=default)
    ttk.Combobox(win, textvariable=var, values=list(options), state="readonly").pack(padx=12, pady=4)
    result: dict[str, str] = {}

    def ok() -> None:
        result["value"] = var.get()
        win.destroy()
    ttk.Button(win, text="OK", command=ok).pack(pady=8)
    root.wait_window(win)
    return result.get("value")


def main(argv: list[str] | None = None) -> int:
    """Launch the KSIF GUI."""
    import main as ksif_main
    root_path = ksif_main.ROOT  # frozen-aware: next to the exe, or the repo root
    engine, db, _settings, _scope = ksif_main.build_engine(root_path)
    window = tk.Tk()
    try:
        KsifGui(window, engine, root_path / "config")
        window.mainloop()
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

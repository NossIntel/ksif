import io

import pytest
from rich.console import Console

import main as ksif_main
from core.models import Host, Mode, Port
from modules.network_discovery import actions as net_actions
from tests.conftest import events, fixture_text
from ui.app import MAIN_MENU, App
from ui.theme import THEME


def make_app(engine, answers, config_dir=None):
    console = Console(file=io.StringIO(), theme=THEME, width=200, record=True, force_terminal=False)
    feed = iter(answers)

    def ask(_prompt):
        try:
            return next(feed)
        except StopIteration:
            raise EOFError from None

    return App(engine, console, ask, config_dir), console


@pytest.fixture
def engine(make_engine):
    engine = make_engine()
    net_actions.register(engine)
    return engine


def test_main_menu_lists_ten_items_and_exit(engine):
    app, console = make_app(engine, ["10"])
    assert app.run() == 0
    text = console.export_text()
    expected = ["[01] Network Discovery", "[02] OSINT Intelligence", "[03] Web Security Assessment",
                "[04] Wi-Fi Security Audit", "[05] Password Security Lab", "[06] Vulnerability Intelligence",
                "[07] Asset Inventory", "[08] Report Generator", "[09] Configuration", "[10] Exit"]
    for item in expected:
        assert item.replace("] ", "]") in text.replace("│", "").replace("  ", " ").replace("] ", "]") or item in text
    assert len(MAIN_MENU) == 10
    assert "Operator" in text and "tester" in text and "ACTIVE" in text


def test_eof_on_input_exits_cleanly(engine):
    app, console = make_app(engine, [])
    assert app.run() == 0
    assert "Session closed" in console.export_text()


def test_all_modules_available(engine):
    """With modules 01-06 implemented, the main menu shows no 'not yet available'."""
    from main import build_engine
    full, db, _s, _sc = build_engine(engine.settings.database_path.parent.parent)
    try:
        app, console = make_app(full, ["10"])
        app.run()
        assert "not yet available" not in console.export_text()
        for module in ("osint", "web_security", "wifi_audit", "password_lab",
                       "vulnerability_intelligence"):
            assert full.actions(module), f"{module} has no actions"
    finally:
        db.close()


def test_unknown_option(engine):
    app, console = make_app(engine, ["99", "abc", "10"])
    app.run()
    assert console.export_text().count("Unknown option") == 2


def test_network_action_out_of_scope_shows_block(engine, db, fake_dir):
    app, console = make_app(engine, ["1", "3", "8.8.8.8", "", "", "0", "10"])
    app.run()
    text = console.export_text()
    assert "BLOCKED" in text and "not in the authorized scope" in text
    assert not list(fake_dir.glob("*.args"))


def test_network_action_runs_and_shows_hosts(engine, db, fake_dir):
    (fake_dir / "nmap.out").write_text(fixture_text("nmap_full.xml"), encoding="utf-8")
    # 01 -> action 3 (port scan) -> target -> ports -> confirm y -> pause -> back -> exit
    app, console = make_app(engine, ["01", "03", "192.168.1.0/24", "22,80", "y", "", "0", "10"])
    app.run()
    text = console.export_text()
    assert "COMPLETED" in text and "192.168.1.50" in text and "Dropbear" in text
    assert len(db.list_hosts()) == 3


def test_declining_confirmation_runs_nothing(engine, fake_dir, db):
    app, console = make_app(engine, ["1", "3", "192.168.1.1", "", "n", "", "0", "10"])
    app.run()
    assert "BLOCKED" in console.export_text() and not list(fake_dir.glob("*.args"))
    assert "confirmation_declined" in events(db)


def test_intrusive_confirmation_requires_typing_target(engine, fake_dir):
    (fake_dir / "masscan.out").write_text(fixture_text("masscan.json"), encoding="utf-8")
    wrong, console = make_app(engine, ["1", "6", "192.168.1.0/24", "", "", "y", "", "0", "10"])
    wrong.run()
    assert "BLOCKED" in console.export_text() and not (fake_dir / "masscan.args").exists()
    right, console = make_app(engine, ["1", "6", "192.168.1.0/24", "", "", "192.168.1.0/24", "", "0", "10"])
    right.run()
    assert "COMPLETED" in console.export_text() and (fake_dir / "masscan.args").exists()


def test_missing_tool_shown_in_module_menu(make_engine):
    engine = make_engine(available=set())
    net_actions.register(engine)
    app, console = make_app(engine, ["1", "0", "10"])
    app.run()
    assert "missing tool: nmap" in console.export_text()


def test_asset_inventory_lists_saved_hosts(engine, db):
    op = db.create_operation("m", "a", "t", "o", "active")
    db.save_hosts(op, [Host("192.168.1.9", "ipv4", vendor="[bold]Acme[/bold]", ports=[Port(22, "tcp", "open", "ssh")])])
    db.finish_operation(op, "completed")
    app, console = make_app(engine, ["7", "1", "2", "3", "8", "4", "0", "10"])
    app.run()
    text = console.export_text()
    assert "192.168.1.9" in text and "22/tcp" in text and "192.168.1.0/24" in text
    assert "[bold]Acme[/bold]" in text  # tool-controlled text is shown literally, never as markup
    assert "Nothing stored yet" in text  # findings are empty


@pytest.mark.parametrize("fmt,ext", [("json", ".json"), ("md", ".md"), ("", ".html"), ("csv", ".csv")])
def test_report_menu_writes_file(engine, settings, db, fmt, ext):
    op = db.create_operation("m", "a", "t", "o", "active")
    db.finish_operation(op, "completed")
    app, console = make_app(engine, ["8", "1", fmt, "10"])
    app.run()
    files = list(settings.reports_dir.glob("ksif_*"))
    assert len(files) == 1 and files[0].suffix == ext
    assert "Report written" in console.export_text()


def test_report_for_unknown_operation(engine, settings):
    app, console = make_app(engine, ["8", "2", "999", "10"])
    app.run()
    assert "No such operation" in console.export_text()
    assert not settings.reports_dir.exists() or not list(settings.reports_dir.iterdir())


def test_toggle_mode_updates_engine_audit_and_file(make_engine, db, tmp_path):
    engine = make_engine(mode=Mode.PASSIVE)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    declined, _ = make_app(engine, ["9", "1", "n", "0", "10"], config_dir)
    declined.run()
    assert engine.settings.mode is Mode.PASSIVE
    app, console = make_app(engine, ["9", "1", "y", "0", "10"], config_dir)
    app.run()
    assert engine.settings.mode is Mode.ACTIVE
    assert "settings_changed" in events(db)
    assert "mode: active" in (config_dir / "settings.yaml").read_text()


def test_configuration_shows_scope_errors_and_tool_check(make_engine, scope, fake_dir):
    scope.errors.append("ips: invalid entry 'nope'")
    engine = make_engine()
    (fake_dir / "nmap.out").write_text("Nmap version 7.95 ( https://nmap.org )", encoding="utf-8")
    app, console = make_app(engine, ["9", "4", "5", "0", "10"])
    app.run()
    text = console.export_text()
    assert "scope problem" in text and "invalid entry 'nope'" in text
    assert "7.95" in text and "unexpected output" in text  # nmap ok, the others print nothing


# ---------------------------------------------------------------- main.py
def test_check_flag_creates_defaults_and_exits_zero(tmp_path, capsys):
    assert ksif_main.main(["--check", "--root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "health check" in out and "nmap" in out and "scope: EMPTY" in out
    assert (tmp_path / "config" / "scope.yaml").exists()
    assert (tmp_path / "database" / "ksif.db").exists()
    assert (tmp_path / "logs" / "ksif.log").exists()


def test_check_with_malformed_scope_does_not_crash(tmp_path, capsys):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "scope.yaml").write_text("ips: [oops", encoding="utf-8")
    assert ksif_main.main(["--check", "--root", str(tmp_path)]) == 0
    assert "scope problem" in capsys.readouterr().out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        ksif_main.main(["--version"])
    assert exc.value.code == 0 and "KSIF" in capsys.readouterr().out


def test_build_engine_registers_network_actions(tmp_path):
    engine, db, _settings, _scope = ksif_main.build_engine(tmp_path)
    try:
        assert len(engine.actions("network_discovery")) == 7
    finally:
        db.close()

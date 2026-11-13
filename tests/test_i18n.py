"""Portuguese localization tests."""

import io

import pytest
from rich.console import Console

from modules.network_discovery import actions as net
from ui import i18n
from ui.app import App
from ui.theme import THEME


@pytest.fixture
def pt():
    i18n.set_language("pt")
    yield
    i18n.set_language("en")


def test_translate_exact_and_phrase(pt):
    assert i18n.t("Configuration") == "Configuração"
    assert i18n.t("Main menu") == "Menu principal"
    assert "não está no escopo autorizado" in i18n.t("8.8.8.8 is not in the authorized scope")
    assert i18n.t("[ksif.key]Run[/]") == "[ksif.key]Executar[/]"


def test_translate_passthrough_for_unknown(pt):
    assert i18n.t("192.168.1.1") == "192.168.1.1"
    assert i18n.t("") == ""


def test_english_is_identity():
    i18n.set_language("en")
    assert i18n.t("Configuration") == "Configuration"


def test_action_localization(pt, make_engine):
    engine = make_engine()
    net.register(engine)
    action = next(a for a in engine.actions("network_discovery") if a.id == "net.host_discovery")
    assert i18n.action_title(action) == "Descoberta de hosts (ping sweep)"
    assert "escolha esta ação" in i18n.action_usage(action)
    i18n.set_language("en")
    assert i18n.action_title(action) == "Host discovery (ping sweep)"


def test_set_language_normalises():
    assert i18n.set_language("pt-BR") == "pt"
    assert i18n.set_language("english") == "en"
    assert i18n.set_language("xx") == "en"
    i18n.set_language("en")


def test_tui_renders_portuguese(make_engine, settings):
    settings.language = "pt"
    engine = make_engine()
    net.register(engine)
    console = Console(file=io.StringIO(), theme=THEME, width=200, record=True)
    feed = iter(["10"])
    app = App(engine, console, lambda _p: next(feed), None)
    app.run()
    text = console.export_text()
    assert "Menu principal" in text and "Descoberta de Rede" in text and "Sair" in text
    assert "Sessão encerrada." in text
    i18n.set_language("en")

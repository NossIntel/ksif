"""GUI smoke tests. Skipped automatically where Tk has no display (e.g. CI)."""

import pytest

tk = pytest.importorskip("tkinter")

from modules.network_discovery import actions as net_actions
from ui.gui import KsifGui, _short_dict


@pytest.fixture
def tk_root():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available for Tk")
    root.withdraw()
    yield root
    try:
        root.destroy()
    except tk.TclError:
        pass


def test_short_dict_truncates():
    assert _short_dict({"a": 1, "b": 2}) == "a=1, b=2"
    assert _short_dict({"x": "y" * 500}).endswith("…")


def test_gui_builds_and_lists_actions(tk_root, make_engine, tmp_path):
    engine = make_engine()
    net_actions.register(engine)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    gui = KsifGui(tk_root, engine, config_dir)
    gui._select_module("network_discovery")
    assert gui.action_tree.get_children()  # actions are listed
    assert "operator" in gui.header_label.cget("text")
    # selecting an action populates the form without raising
    first = gui.action_tree.get_children()[0]
    gui.action_tree.selection_set(first)
    gui._on_action(None)
    assert gui.current_action is not None


def test_gui_blocks_out_of_scope(tk_root, make_engine, tmp_path, fake_dir):
    import time
    engine = make_engine()
    net_actions.register(engine)
    gui = KsifGui(tk_root, engine, tmp_path)
    gui.current_action = engine.actions("network_discovery")[0]  # host discovery
    gui.target_var.set("8.8.8.8")
    gui._run()
    for _ in range(50):
        tk_root.update()
        if not gui.running:
            break
        time.sleep(0.05)
    assert "BLOCKED" in gui.results.get("1.0", "end")

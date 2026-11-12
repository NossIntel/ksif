from core.config import load_scope, load_settings, save_settings
from core.models import Mode


def test_scope_missing_file(tmp_path):
    scope = load_scope(tmp_path / "scope.yaml")
    assert scope.is_empty and scope.errors


def test_scope_malformed_yaml(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("ips: [1.2.3.4\n  subnets: {", encoding="utf-8")
    scope = load_scope(path)
    assert scope.is_empty and "not valid YAML" in scope.errors[0]


def test_scope_top_level_not_mapping(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("- a\n- b\n", encoding="utf-8")
    assert load_scope(path).errors


def test_scope_empty_file_is_empty_scope_without_errors(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("", encoding="utf-8")
    scope = load_scope(path)
    assert scope.is_empty and not scope.errors


def test_scope_invalid_entry_reported(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(
        "engagement: Lab\n"
        "ips: ['10.0.0.1', 'not-an-ip', 5]\n"
        "subnets: ['192.168.1.7/24', '10.0.0.0/99']\n"
        "domains: ['Example.com', '*.lab.test', 'bad domain', '*.*.x']\n"
        "interfaces: ['eth0', '-i']\n"
        "bssids: ['AA-BB-CC-DD-EE-FF', 'zz']\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.engagement == "Lab"
    assert scope.ips == ["10.0.0.1"]
    assert scope.subnets == ["192.168.1.0/24"]
    assert scope.domains == ["example.com", "*.lab.test"]
    assert scope.interfaces == ["eth0"]
    assert scope.bssids == ["aa:bb:cc:dd:ee:ff"]
    assert len(scope.errors) == 7


def test_scope_list_key_wrong_type(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("ips: '10.0.0.1'\n", encoding="utf-8")
    scope = load_scope(path)
    assert scope.ips == [] and scope.errors


def test_settings_defaults_and_operator_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("KSIF_OPERATOR", "bob")
    settings = load_settings(tmp_path / "config" / "settings.yaml", root=tmp_path)
    assert settings.operator == "bob"
    assert settings.mode is Mode.PASSIVE
    assert settings.database_path == tmp_path / "database" / "ksif.db"


def test_settings_bad_values_fall_back(tmp_path):
    path = tmp_path / "settings.yaml"
    path.write_text("mode: destroy\nrate_limit_seconds: x\ndefault_timeout_seconds: -5\n", encoding="utf-8")
    settings = load_settings(path, root=tmp_path)
    assert settings.mode is Mode.PASSIVE
    assert settings.rate_limit_seconds == 2.0
    assert settings.default_timeout_seconds == 1


def test_settings_roundtrip(tmp_path):
    path = tmp_path / "config" / "settings.yaml"
    settings = load_settings(path, root=tmp_path)
    settings.operator = "carol"
    settings.mode = Mode.ACTIVE
    save_settings(settings, path, root=tmp_path)
    again = load_settings(path, root=tmp_path)
    assert again.operator == "carol" and again.mode is Mode.ACTIVE
    assert again.logs_dir == tmp_path / "logs"

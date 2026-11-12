import pytest

from core.validator import ValidationError, parse_file_target
from integrations.john import JohnIntegration
from modules.password_lab import strength
from modules.password_lab import actions
from tests.conftest import FakeToolRunner


@pytest.fixture
def runner(audit, fake_dir):
    return FakeToolRunner(audit, fake_dir)


def yes(_p):
    return True


# ---------------------------------------------------------------- strength
@pytest.mark.parametrize("pw,verdict", [
    ("password", "very weak"), ("123456", "very weak"), ("aaaaaa", "very weak"),
    ("abcd1234", "weak"), ("Tr0ub4dor", "fair"),
    ("correct-horse-battery-staple-42", "very strong"),
])
def test_analyze_verdicts(pw, verdict):
    assert strength.analyze(pw).verdict == verdict


def test_analyze_issues():
    result = strength.analyze("password", 12)
    assert result.is_weak
    assert any("common" in i for i in result.issues)
    assert any("shorter" in i for i in result.issues)
    assert strength.analyze("12345678").issues  # all digits + sequence


def test_entropy_increases_with_variety():
    assert strength.entropy_bits("aaaa") < strength.entropy_bits("aA1$bcde")


def test_audit_list():
    report = strength.audit_list(["password", "password", "123456", "Str0ng-Passphrase-Example!!"], 12)
    assert report.total == 4 and report.weak == 3
    assert report.common == 3 and report.reused == 2
    assert report.weakest_examples and "(len" in report.weakest_examples[0]
    # masked labels never reveal the full password
    assert "password" not in report.weakest_examples[0]


# ---------------------------------------------------------------- john
def test_john_args(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("a\nb\n", encoding="utf-8")
    hashes = tmp_path / "hashes.txt"
    hashes.write_text("x", encoding="utf-8")
    target = parse_file_target(str(hashes))
    tool = JohnIntegration(None)
    args = tool.crack_args(target, str(wl), "raw-md5")
    assert args[0].startswith("--wordlist=") and "--format=raw-md5" in args
    assert args[-1] == str(hashes.resolve())
    assert tool.show_args(target)[0] == "--show"
    with pytest.raises(ValidationError):
        tool.crack_args(target, str(wl), "bad;format")
    with pytest.raises(ValidationError):
        tool.crack_args(target, str(tmp_path / "missing.txt"))


def test_john_parse_show():
    out = "user1:secret:1001:::\nuser2:summer2020:1002:::\n\n2 password hashes cracked, 3 left\n"
    assert JohnIntegration(None).parse_show(out) == {"cracked": 2, "remaining": 3}
    assert JohnIntegration(None).parse_version("John the Ripper 1.9.0-jumbo-1 ...") == "1.9.0-jumbo-1"


# ---------------------------------------------------------------- actions
@pytest.fixture
def pw_engine(make_engine):
    def build(**kw):
        engine = make_engine(**kw)
        actions.register(engine)
        return engine
    return build


def test_all_actions_offline(pw_engine):
    acts = pw_engine().actions("password_lab")
    assert {a.id for a in acts} == {"pass.analyze", "pass.policy_audit", "pass.compromised", "pass.hash_audit"}
    assert all(a.intrusiveness.name == "PASSIVE" for a in acts)
    assert all(a.consent for a in acts if a.id != "pass.analyze")


async def test_analyze_does_not_store_password(pw_engine, db):
    result = await pw_engine().execute("pass.analyze", "", {"password": "password"}, confirm=yes)
    assert result.status == "completed", result.error
    assert result.output.data["verdict"] == "very weak"
    # the password itself is nowhere in the stored operation/audit data
    blob = str(db.list_operations()) + str(db.list_audit())
    assert "password=password" not in blob


async def test_policy_audit_file(pw_engine, db, tmp_path):
    pwfile = tmp_path / "pwlist.txt"
    pwfile.write_text("password\n123456\nStr0ng-Passphrase!!\nqwerty\n", encoding="utf-8")
    result = await pw_engine().execute("pass.policy_audit", str(pwfile), {"min_length": "12"}, confirm=yes)
    assert result.status == "completed", result.error
    assert result.output.data["weak"] == 3
    assert any(f["severity"] in ("high", "medium") for f in db.list_findings([result.op_id]))


async def test_compromised_check(pw_engine, db, tmp_path):
    breach = tmp_path / "rockyou.txt"
    breach.write_text("password\n123456\nletmein\n", encoding="utf-8")
    mine = tmp_path / "mine.txt"
    mine.write_text("password\nUniqueOne!\n123456\n", encoding="utf-8")
    result = await pw_engine().execute("pass.compromised", str(mine), {"wordlist": str(breach)}, confirm=yes)
    assert result.status == "completed", result.error
    assert result.output.data["compromised"] == 2
    assert any(f["severity"] == "critical" for f in db.list_findings([result.op_id]))


async def test_hash_audit_runs_john(pw_engine, db, fake_dir, tmp_path):
    (fake_dir / "john.out").write_text("admin:winter2021:::\n\n1 password hash cracked, 2 left\n", encoding="utf-8")
    wl = tmp_path / "wl.txt"
    wl.write_text("winter2021\n", encoding="utf-8")
    hashes = tmp_path / "shadow.txt"
    hashes.write_text("admin:$1$abc$def:::\n", encoding="utf-8")
    result = await pw_engine().execute("pass.hash_audit", str(hashes), {"wordlist": str(wl)}, confirm=yes)
    assert result.status == "completed", result.error
    assert result.output.data == {"cracked": 1, "remaining": 2}
    assert any("recovered" in f["title"] for f in db.list_findings([result.op_id]))


async def test_consent_declined_blocks(pw_engine, tmp_path):
    pwfile = tmp_path / "p.txt"
    pwfile.write_text("password\n", encoding="utf-8")
    result = await pw_engine().execute("pass.policy_audit", str(pwfile), confirm=lambda _p: False)
    assert result.status == "blocked" and "consent" in result.error.lower()


async def test_missing_file_blocked(pw_engine, tmp_path):
    result = await pw_engine().execute("pass.policy_audit", str(tmp_path / "nope.txt"), confirm=yes)
    assert result.status == "blocked" and "invalid target" in result.error

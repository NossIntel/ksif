import pytest

from core.engine import Action, ActionOutput, RateLimiter
from core.models import Host, Intrusiveness, Mode, Port, TargetKind
from tests.conftest import events

NET = frozenset({TargetKind.IPV4, TargetKind.IPV6, TargetKind.CIDR, TargetKind.DOMAIN})


def make_action(calls, **kw):
    async def handler(ctx, params):
        calls.append((ctx.target.value, params))
        if params.get("boom"):
            raise RuntimeError("tool exploded")
        return ActionOutput(
            hosts=[Host("192.168.1.9", "ipv4", ports=[Port(22, "tcp", "open")])], summary="1 host"
        )

    defaults = dict(
        id="t.scan", module="test", title="Test scan", intrusiveness=Intrusiveness.ACTIVE,
        target_kinds=NET, required_tools=("nmap",), requires_root=False, handler=handler,
    )
    defaults.update(kw)
    return Action(**defaults)


def yes(_prompt):
    return True


async def test_happy_path_persists_hosts(make_engine, db):
    calls = []
    engine = make_engine()
    engine.register(make_action(calls))
    result = await engine.execute("t.scan", "192.168.1.9", {"x": 1}, confirm=yes)
    assert result.status == "completed" and result.error is None
    assert calls == [("192.168.1.9", {"x": 1})]
    assert [h.address for h in db.list_hosts(result.op_id)] == ["192.168.1.9"]
    op = db.get_operation(result.op_id)
    assert op["status"] == "completed" and op["operator"] == "tester" and op["summary"] == "1 host"
    assert "scope_allowed" in events(db)


async def test_out_of_scope_blocked_and_audited(make_engine, db):
    calls = []
    engine = make_engine()
    engine.register(make_action(calls))
    result = await engine.execute("t.scan", "8.8.8.8", confirm=yes)
    assert result.status == "blocked" and "not in the authorized scope" in result.error
    assert calls == []
    assert db.get_operation(result.op_id)["status"] == "blocked"
    assert events(db) == ["scope_blocked"]


async def test_passive_mode_blocks_active_action(make_engine, db):
    calls = []
    engine = make_engine(mode=Mode.PASSIVE)
    engine.register(make_action(calls))
    result = await engine.execute("t.scan", "192.168.1.9", confirm=yes)
    assert result.status == "blocked" and "passive mode" in result.error
    assert calls == [] and events(db) == ["mode_blocked"]


@pytest.mark.parametrize("raw", ["-oN /tmp/x", "1.2.3.4; id", ""])
async def test_invalid_target_blocked(make_engine, db, raw):
    calls = []
    engine = make_engine()
    engine.register(make_action(calls))
    result = await engine.execute("t.scan", raw, confirm=yes)
    assert result.status == "blocked" and "invalid target" in result.error
    assert calls == [] and events(db) == ["invalid_target"]


async def test_wrong_target_kind_blocked(make_engine):
    calls = []
    engine = make_engine()
    engine.register(make_action(calls))
    result = await engine.execute("t.scan", "http://192.168.1.9/", confirm=yes)
    assert result.status == "blocked" and "accepts only" in result.error and calls == []


async def test_confirmation_declined(make_engine, db):
    calls, prompts = [], []
    engine = make_engine()
    engine.register(make_action(calls))

    def no(prompt):
        prompts.append(prompt)
        return False

    result = await engine.execute("t.scan", "192.168.1.9", confirm=no)
    assert result.status == "blocked" and calls == []
    assert "192.168.1.9" in prompts[0] and "ACTIVE" in prompts[0] and "tester" in prompts[0]
    assert events(db) == ["confirmation_declined"]


async def test_passive_action_skips_confirmation(make_engine):
    calls = []
    engine = make_engine(mode=Mode.PASSIVE)
    engine.register(make_action(calls, intrusiveness=Intrusiveness.PASSIVE))

    def never(_prompt):
        raise AssertionError("must not ask")

    result = await engine.execute("t.scan", "192.168.1.9", confirm=never)
    assert result.status == "completed"


async def test_consent_statement_always_asked(make_engine):
    calls, prompts = [], []
    engine = make_engine()
    engine.register(make_action(calls, intrusiveness=Intrusiveness.PASSIVE, consent="I own this data"))
    result = await engine.execute("t.scan", "192.168.1.9", confirm=lambda p: prompts.append(p) or False)
    assert result.status == "blocked" and calls == [] and "I own this data" in prompts[0]


async def test_missing_tool_blocked(make_engine):
    calls = []
    engine = make_engine(available=set())
    action = make_action(calls)
    engine.register(action)
    assert engine.availability(action) == (False, "missing tool: nmap")
    result = await engine.execute("t.scan", "192.168.1.9", confirm=yes)
    assert result.status == "blocked" and "missing tool" in result.error and calls == []


async def test_any_tool_availability(make_engine):
    engine = make_engine(available={"dig"})
    action = make_action([], required_tools=("whois", "dig"), any_tool=True)
    assert engine.availability(action)[0] is True
    strict = make_action([], id="t.2", required_tools=("whois", "dig"))
    assert engine.availability(strict) == (False, "missing tool: whois")


async def test_requires_root_blocked(make_engine):
    calls = []
    engine = make_engine(root=False)
    engine.register(make_action(calls, requires_root=True))
    result = await engine.execute("t.scan", "192.168.1.9", confirm=yes)
    assert result.status == "blocked" and "root" in result.error and calls == []


async def test_handler_exception_marks_failed_and_saves_nothing(make_engine, db):
    engine = make_engine()
    engine.register(make_action([]))
    result = await engine.execute("t.scan", "192.168.1.9", {"boom": True}, confirm=yes)
    assert result.status == "failed" and "tool exploded" in result.error
    assert db.list_hosts() == []
    assert db.get_operation(result.op_id)["status"] == "failed"
    assert "operation_failed" in events(db)


async def test_local_target_action(make_engine):
    calls = []
    engine = make_engine(mode=Mode.PASSIVE)
    engine.register(make_action(calls, intrusiveness=Intrusiveness.PASSIVE,
                                target_kinds=frozenset({TargetKind.NONE}), required_tools=()))
    result = await engine.execute("t.scan", "", confirm=yes)
    assert result.status == "completed" and calls[0][0] == "local"


async def test_set_mode_is_audited_and_effective(make_engine, db):
    calls = []
    engine = make_engine(mode=Mode.PASSIVE)
    engine.register(make_action(calls))
    engine.set_mode(Mode.ACTIVE)
    assert (await engine.execute("t.scan", "192.168.1.9", confirm=yes)).status == "completed"
    assert "settings_changed" in events(db)


def test_duplicate_action_id(make_engine):
    engine = make_engine()
    engine.register(make_action([]))
    with pytest.raises(ValueError):
        engine.register(make_action([]))


async def test_rate_limiter_spaces_calls():
    now = [100.0]
    slept = []

    async def sleep(seconds):
        slept.append(round(seconds, 3))
        now[0] += seconds

    limiter = RateLimiter(2.0, clock=lambda: now[0], sleep=sleep)
    await limiter.wait()
    now[0] += 0.5
    await limiter.wait()
    now[0] += 5
    await limiter.wait()
    assert slept == [1.5]

import json

import pytest

from core.database import Database
from core.logger import AuditLogger, add_line_listener, setup_logging
from core.models import Host, Port


def host(addr="192.168.1.10", **kw):
    return Host(address=addr, family="ipv4", **kw)


def test_migrate_idempotent(db):
    first = db.migrate()
    assert first >= 1 and db.migrate() == first


def test_file_database_created(tmp_path):
    database = Database(tmp_path / "nested" / "k.db")
    assert database.migrate() >= 1
    database.close()
    assert (tmp_path / "nested" / "k.db").exists()


def test_operation_lifecycle(db):
    op = db.create_operation("network_discovery", "net.port_scan", "192.168.1.1", "alice", "active")
    assert db.get_operation(op)["status"] == "running"
    db.finish_operation(op, "completed", summary="1 host")
    row = db.get_operation(op)
    assert row["status"] == "completed" and row["finished_at"] and row["summary"] == "1 host"
    assert db.list_operations()[0]["id"] == op
    with pytest.raises(ValueError):
        db.finish_operation(op, "weird")


def test_save_hosts_roundtrip(db):
    op = db.create_operation("m", "a", "t", "o", "active")
    original = host(
        mac="AA:BB:CC:00:11:22", vendor="Acme", hostname="gw", os_guess="Linux 5.x", os_accuracy=96,
        device_type="router", hops=["10.0.0.1", "192.168.1.10"],
        ports=[Port(22, "tcp", "open", "ssh", "OpenSSH", "9.6"), Port(53, "udp", "open", "domain")],
    )
    db.save_hosts(op, [original])
    assert db.list_hosts() == [original]
    assert db.list_hosts(op) == [original]


def test_upsert_updates_existing_host(db):
    op1 = db.create_operation("m", "a", "t", "o", "active")
    db.save_hosts(op1, [host(vendor="Acme", ports=[Port(80, "tcp", "open", "http")])])
    op2 = db.create_operation("m", "a", "t", "o", "active")
    db.save_hosts(op2, [host(os_guess="Linux", ports=[Port(80, "tcp", "open", "http", "nginx", "1.24")])])
    hosts = db.list_hosts()
    assert len(hosts) == 1
    assert hosts[0].vendor == "Acme" and hosts[0].os_guess == "Linux"
    assert len(hosts[0].ports) == 1 and hosts[0].ports[0].product == "nginx"
    row = db.query("SELECT first_seen_op, last_seen_op FROM hosts")[0]
    assert (row["first_seen_op"], row["last_seen_op"]) == (op1, op2)
    assert len(db.list_hosts(op1)) == 1 and len(db.list_hosts(op2)) == 1


def test_save_hosts_atomic(db):
    op = db.create_operation("m", "a", "t", "o", "active")
    with pytest.raises(ValueError):
        db.save_hosts(op, [host("192.168.1.1"), host("not-an-ip"), host("192.168.1.3")])
    assert db.list_hosts() == []


def test_list_hosts_by_operation(db):
    op1 = db.create_operation("m", "a", "t", "o", "active")
    op2 = db.create_operation("m", "a", "t", "o", "active")
    db.save_hosts(op1, [host("192.168.1.1")])
    db.save_hosts(op2, [host("192.168.1.2")])
    assert [h.address for h in db.list_hosts(op2)] == ["192.168.1.2"]
    assert len(db.list_hosts()) == 2


def test_generic_insert_rejects_unsafe_identifier(db):
    with pytest.raises(ValueError):
        db.insert("hosts; DROP TABLE hosts", {"a": 1})
    with pytest.raises(ValueError):
        db.insert("hosts", {"a) VALUES (1); --": 1})


def test_audit_record_written_as_json_line_and_db(tmp_path, db):
    audit = AuditLogger(tmp_path / "logs", db)
    audit.record("scope_blocked", operator="alice", target="8.8.8.8", reason="out of scope")
    line = json.loads((tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8").strip())
    assert line["event"] == "scope_blocked" and line["operator"] == "alice" and line["ts"].endswith("+00:00")
    row = db.list_audit()[0]
    assert row["event"] == "scope_blocked" and row["detail"]["target"] == "8.8.8.8"


def test_log_lines_are_valid_json_and_listener(tmp_path):
    logger = setup_logging(tmp_path)
    seen: list[str] = []
    remove = add_line_listener(seen.append)
    logger.info("hello %s", "world")
    remove()
    logger.info("after")
    for handler in logger.handlers:
        handler.flush()
    lines = (tmp_path / "ksif.log").read_text(encoding="utf-8").strip().splitlines()
    assert [json.loads(line)["message"] for line in lines] == ["hello world", "after"]
    assert len(seen) == 1 and "hello world" in seen[0]

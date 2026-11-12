"""SQLite persistence with versioned migrations."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.models import Host, Port

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def utc_now() -> str:
    """Current UTC time as ISO-8601 (seconds precision)."""
    return datetime.now(UTC).isoformat(timespec="seconds")


class Database:
    """Thin, typed wrapper around the KSIF SQLite database."""

    def __init__(self, path: Path | str) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    # -- schema ------------------------------------------------------------
    def migrate(self) -> int:
        """Apply pending ``core/migrations/NNN_*.sql`` files; return the version."""
        self.conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        row = self.conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
        current = row["v"] or 0
        for script in sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql")):
            version = int(script.name[:3])
            if version <= current:
                continue
            self.conn.executescript("BEGIN;\n" + script.read_text(encoding="utf-8") + "\nCOMMIT;")
            self.conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
            self.conn.commit()
            current = version
        return current

    # -- generic helpers (used by module-specific tables) -----------------
    def insert(self, table: str, row: dict[str, Any]) -> int:
        """Insert *row* into *table*; column names come from code, never users."""
        self._check_identifier(table, *row)
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        with self.conn:
            cur = self.conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(row.values()))
        return int(cur.lastrowid or 0)

    def insert_many(self, table: str, rows: list[dict[str, Any]]) -> None:
        """Insert several rows atomically."""
        if not rows:
            return
        self._check_identifier(table, *rows[0])
        cols = ", ".join(rows[0])
        marks = ", ".join("?" for _ in rows[0])
        with self.conn:
            self.conn.executemany(
                f"INSERT INTO {table} ({cols}) VALUES ({marks})", [tuple(r.values()) for r in rows]
            )

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        """Run a read query and return rows as dicts."""
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    @staticmethod
    def _check_identifier(*names: str) -> None:
        for name in names:
            if not name.replace("_", "").isalnum():
                raise ValueError(f"unsafe SQL identifier: {name!r}")

    # -- operations --------------------------------------------------------
    def create_operation(
        self,
        module: str,
        action: str,
        target: str,
        operator: str,
        intrusiveness: str,
        command: str = "",
    ) -> int:
        """Register a new operation in state ``running``."""
        return self.insert(
            "operations",
            {
                "module": module,
                "action": action,
                "target": target,
                "operator": operator,
                "intrusiveness": intrusiveness,
                "command": command,
                "started_at": utc_now(),
            },
        )

    def finish_operation(
        self,
        op_id: int,
        status: str,
        error: str | None = None,
        raw_output_path: str | None = None,
        summary: str | None = None,
    ) -> None:
        """Close an operation as ``completed``, ``failed`` or ``blocked``."""
        if status not in ("completed", "failed", "blocked"):
            raise ValueError(f"invalid status {status!r}")
        with self.conn:
            self.conn.execute(
                "UPDATE operations SET status=?, error=?, summary=?, "
                "raw_output_path=COALESCE(?, raw_output_path), finished_at=? WHERE id=?",
                (status, error, summary, raw_output_path, utc_now(), op_id),
            )

    def set_operation_command(self, op_id: int, command: str, raw_output_path: str | None = None) -> None:
        """Record the exact command line (and raw output file) of an operation."""
        with self.conn:
            self.conn.execute(
                "UPDATE operations SET command=?, raw_output_path=COALESCE(?, raw_output_path) WHERE id=?",
                (command, raw_output_path, op_id),
            )

    def get_operation(self, op_id: int) -> dict[str, Any] | None:
        """Return one operation or None."""
        rows = self.query("SELECT * FROM operations WHERE id=?", (op_id,))
        return rows[0] if rows else None

    def list_operations(self, limit: int = 50) -> list[dict[str, Any]]:
        """Most recent operations first."""
        return self.query("SELECT * FROM operations ORDER BY id DESC LIMIT ?", (limit,))

    # -- hosts ---------------------------------------------------------------
    def save_hosts(self, op_id: int, hosts: list[Host]) -> None:
        """Upsert hosts and their ports in a single transaction."""
        now = utc_now()
        with self.conn:  # commits on success, rolls back on any exception
            for host in hosts:
                address = ipaddress.ip_address(host.address).compressed  # ValueError if bad
                row = self.conn.execute("SELECT id FROM hosts WHERE address=?", (address,)).fetchone()
                values = (
                    host.family, host.mac, host.vendor, host.hostname, host.os_guess,
                    host.os_accuracy, host.device_type, host.state,
                )
                if row is None:
                    cur = self.conn.execute(
                        "INSERT INTO hosts (address, family, mac, vendor, hostname, os_guess, "
                        "os_accuracy, device_type, state, hops_json, first_seen_op, last_seen_op, "
                        "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (address, *values, json.dumps(host.hops), op_id, op_id, now),
                    )
                    host_id = cur.lastrowid
                else:
                    host_id = row["id"]
                    self.conn.execute(
                        "UPDATE hosts SET family=?, mac=COALESCE(?, mac), vendor=COALESCE(?, vendor), "
                        "hostname=COALESCE(?, hostname), os_guess=COALESCE(?, os_guess), "
                        "os_accuracy=COALESCE(?, os_accuracy), device_type=COALESCE(?, device_type), "
                        "state=?, hops_json=CASE WHEN ?='[]' THEN hops_json ELSE ? END, "
                        "last_seen_op=?, updated_at=? WHERE id=?",
                        (*values, json.dumps(host.hops), json.dumps(host.hops), op_id, now, host_id),
                    )
                self.conn.execute(
                    "INSERT OR IGNORE INTO host_sightings (op_id, host_id) VALUES (?,?)", (op_id, host_id)
                )
                for port in host.ports:
                    self.conn.execute(
                        "INSERT INTO ports (host_id, number, protocol, state, service, product, version, op_id) "
                        "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(host_id, number, protocol) DO UPDATE SET "
                        "state=excluded.state, service=COALESCE(excluded.service, service), "
                        "product=COALESCE(excluded.product, product), "
                        "version=COALESCE(excluded.version, version), op_id=excluded.op_id",
                        (host_id, int(port.number), port.protocol, port.state, port.service,
                         port.product, port.version, op_id),
                    )

    def list_hosts(self, op_id: int | None = None) -> list[Host]:
        """All known hosts, or only those seen by one operation."""
        if op_id is None:
            rows = self.conn.execute("SELECT * FROM hosts ORDER BY id").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT h.* FROM hosts h JOIN host_sightings s ON s.host_id=h.id "
                "WHERE s.op_id=? ORDER BY h.id",
                (op_id,),
            ).fetchall()
        hosts: list[Host] = []
        for row in rows:
            ports = [
                Port(p["number"], p["protocol"], p["state"], p["service"], p["product"], p["version"])
                for p in self.conn.execute(
                    "SELECT * FROM ports WHERE host_id=? ORDER BY number, protocol", (row["id"],)
                )
            ]
            hosts.append(
                Host(
                    address=row["address"], family=row["family"], mac=row["mac"], vendor=row["vendor"],
                    hostname=row["hostname"], os_guess=row["os_guess"], os_accuracy=row["os_accuracy"],
                    device_type=row["device_type"], state=row["state"], ports=ports,
                    hops=json.loads(row["hops_json"]),
                )
            )
        return hosts

    # -- audit and reports -------------------------------------------------
    def add_audit(self, event: dict[str, Any]) -> None:
        """Store one audit record."""
        detail = {k: v for k, v in event.items() if k not in ("ts", "operator", "event")}
        self.insert(
            "audit_log",
            {
                "ts": event.get("ts", utc_now()),
                "operator": event.get("operator", ""),
                "event": event.get("event", ""),
                "detail_json": json.dumps(detail, default=str),
            },
        )

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        """Most recent audit records first."""
        rows = self.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        for row in rows:
            row["detail"] = json.loads(row.pop("detail_json"))
        return rows

    def add_report(self, op_id: int | None, fmt: str, path: str) -> int:
        """Register a generated report file."""
        return self.insert(
            "reports", {"op_id": op_id, "format": fmt, "path": path, "created_at": utc_now()}
        )

    def close(self) -> None:
        """Close the connection."""
        self.conn.close()

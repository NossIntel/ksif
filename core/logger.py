"""Structured (JSON Lines) logging and the audit trail."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.database import Database

LOGGER_NAME = "ksif"
_listeners: list[Callable[[str], None]] = []


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="seconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class _ListenerHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        line = f"{record.levelname:<7} {record.getMessage()}"
        for callback in list(_listeners):
            try:
                callback(line)
            except Exception:  # noqa: BLE001 - a broken UI listener must not break logging
                pass


def add_line_listener(callback: Callable[[str], None]) -> Callable[[], None]:
    """Subscribe to human-readable log lines; returns an unsubscribe function."""
    _listeners.append(callback)

    def remove() -> None:
        if callback in _listeners:
            _listeners.remove(callback)

    return remove


def setup_logging(logs_dir: Path) -> logging.Logger:
    """Configure the ``ksif`` logger to write JSON Lines to ``logs/ksif.log``."""
    logs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    file_handler = logging.FileHandler(logs_dir / "ksif.log", encoding="utf-8")
    file_handler.setFormatter(_JsonFormatter())
    logger.addHandler(file_handler)
    logger.addHandler(_ListenerHandler())
    return logger


class AuditLogger:
    """Append-only audit trail: ``logs/audit.jsonl`` plus the database."""

    def __init__(self, logs_dir: Path, db: Database | None = None) -> None:
        logs_dir.mkdir(parents=True, exist_ok=True)
        self.path = logs_dir / "audit.jsonl"
        self._db = db

    def record(self, event: str, *, operator: str, **detail: Any) -> dict[str, Any]:
        """Write one audit record and return it."""
        entry: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "operator": operator,
            "event": event,
            **detail,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        if self._db is not None:
            self._db.add_audit(entry)
        logging.getLogger(LOGGER_NAME).info("audit %s %s", event, json.dumps(detail, default=str))
        return entry

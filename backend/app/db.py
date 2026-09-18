"""SQLite persistence: analyses, correlation indicators, lookup cache and chain-of-custody log."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id            TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    sent_at       TEXT NOT NULL,          -- best estimate of when the message was sent (UTC)
    sha256        TEXT NOT NULL,
    subject       TEXT NOT NULL,
    from_address  TEXT NOT NULL,
    from_domain   TEXT NOT NULL,
    sender_key    TEXT NOT NULL,          -- from domain, or full address for free-mail senders
    origin_ip     TEXT,
    country       TEXT,
    asn           TEXT,
    score         INTEGER NOT NULL,
    level         TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    result_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_analyses_created ON analyses(created_at);
CREATE INDEX IF NOT EXISTS ix_analyses_ip_sent ON analyses(origin_ip, sent_at);
CREATE INDEX IF NOT EXISTS ix_analyses_sender_sent ON analyses(sender_key, sent_at);
CREATE INDEX IF NOT EXISTS ix_analyses_sha ON analyses(sha256);

CREATE TABLE IF NOT EXISTS indicators (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    PRIMARY KEY (analysis_id, kind, value)
);
CREATE INDEX IF NOT EXISTS ix_indicators_lookup ON indicators(kind, value);

CREATE TABLE IF NOT EXISTS cache (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS custody_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    event       TEXT NOT NULL,
    at          TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_custody_analysis ON custody_log(analysis_id);
"""


def utcnow() -> datetime:
    return datetime.now(UTC)


class Database:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._local = threading.local()
        with self.connect() as conn:
            conn.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = self._conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # --- cache -------------------------------------------------------------

    def cache_get(self, key: str) -> Any | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value, expires_at FROM cache WHERE key = ?", (key,)).fetchone()
        if row is None or row["expires_at"] < utcnow().isoformat():
            return None
        return json.loads(row["value"])

    def cache_set(self, key: str, value: Any, ttl_hours: float) -> None:
        expires = (utcnow() + timedelta(hours=ttl_hours)).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO cache(key, value, expires_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at",
                (key, json.dumps(value, default=str), expires),
            )

    # --- custody -----------------------------------------------------------

    def log_custody(self, analysis_id: str, sha256: str, event: str, detail: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO custody_log(analysis_id, sha256, event, at, detail) VALUES (?, ?, ?, ?, ?)",
                (analysis_id, sha256, event, utcnow().isoformat(), detail),
            )

    def custody_events(self, analysis_id: str) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT event, at, detail FROM custody_log WHERE analysis_id = ? ORDER BY id", (analysis_id,)
            ).fetchall()

    # --- retention ---------------------------------------------------------

    def purge_older_than(self, days: int) -> list[str]:
        cutoff = (utcnow() - timedelta(days=days)).isoformat()
        with self.connect() as conn:
            rows = conn.execute("SELECT id, sha256 FROM analyses WHERE created_at < ?", (cutoff,)).fetchall()
            conn.execute("DELETE FROM analyses WHERE created_at < ?", (cutoff,))
            conn.execute("DELETE FROM cache WHERE expires_at < ?", (utcnow().isoformat(),))
            for row in rows:
                conn.execute(
                    "INSERT INTO custody_log(analysis_id, sha256, event, at, detail) VALUES (?, ?, 'purged', ?, ?)",
                    (row["id"], row["sha256"], utcnow().isoformat(), f"retention policy: {days} days"),
                )
        return [row["sha256"] for row in rows]

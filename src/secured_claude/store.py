"""Append-only SQLite audit store (ADR-0004).

INSERT-only schema enforced by triggers that ABORT on UPDATE/DELETE. The DB
file is created with mode 0o600 so the host user is the only reader on
multi-tenant Linux machines.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secured_claude._paths import db_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    principal_id    TEXT NOT NULL,
    principal_roles TEXT NOT NULL,
    resource_kind   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    action          TEXT NOT NULL,
    decision        TEXT NOT NULL CHECK(decision IN ('ALLOW','DENY')),
    args_json       TEXT,
    cerbos_reason   TEXT,
    duration_ms     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_approvals_principal
    ON approvals(principal_id);
CREATE INDEX IF NOT EXISTS idx_approvals_resource_action
    ON approvals(resource_kind, action);
CREATE INDEX IF NOT EXISTS idx_approvals_ts
    ON approvals(ts);

CREATE TRIGGER IF NOT EXISTS approvals_no_update
    BEFORE UPDATE ON approvals
    BEGIN
        SELECT RAISE(ABORT, 'append-only: UPDATE forbidden');
    END;

CREATE TRIGGER IF NOT EXISTS approvals_no_delete
    BEFORE DELETE ON approvals
    BEGIN
        SELECT RAISE(ABORT, 'append-only: DELETE forbidden');
    END;
"""


@dataclass(frozen=True)
class Approval:
    """One row of the audit log."""

    id: int
    ts: str
    session_id: str
    principal_id: str
    principal_roles: list[str]
    resource_kind: str
    resource_id: str
    action: str
    decision: str
    args_json: str | None
    cerbos_reason: str | None
    duration_ms: int | None


class Store:
    """SQLite-backed append-only store for approval decisions."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or db_path()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def insert(
        self,
        session_id: str,
        principal_id: str,
        principal_roles: list[str],
        resource_kind: str,
        resource_id: str,
        action: str,
        decision: str,
        args: dict[str, Any] | None = None,
        cerbos_reason: str | None = None,
        duration_ms: int | None = None,
    ) -> int:
        if decision not in ("ALLOW", "DENY"):
            raise ValueError(f"decision must be ALLOW or DENY, got {decision!r}")
        ts = datetime.now(UTC).isoformat(timespec="milliseconds")
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO approvals (
                    ts, session_id, principal_id, principal_roles,
                    resource_kind, resource_id, action, decision,
                    args_json, cerbos_reason, duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    session_id,
                    principal_id,
                    json.dumps(principal_roles),
                    resource_kind,
                    resource_id,
                    action,
                    decision,
                    json.dumps(args) if args is not None else None,
                    cerbos_reason,
                    duration_ms,
                ),
            )
            return int(cur.lastrowid or 0)

    def query(
        self,
        decision: str | None = None,
        principal_id: str | None = None,
        resource_kind: str | None = None,
        action: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[Approval]:
        sql = "SELECT * FROM approvals WHERE 1=1"
        params: list[Any] = []
        if decision is not None:
            sql += " AND decision = ?"
            params.append(decision)
        if principal_id is not None:
            sql += " AND principal_id = ?"
            params.append(principal_id)
        if resource_kind is not None:
            sql += " AND resource_kind = ?"
            params.append(resource_kind)
        if action is not None:
            sql += " AND action = ?"
            params.append(action)
        if since is not None:
            sql += " AND ts >= ?"
            params.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_approval(r) for r in rows]

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM approvals").fetchone()
        return int(row["n"])

    @staticmethod
    def _row_to_approval(row: sqlite3.Row) -> Approval:
        roles_raw = row["principal_roles"]
        roles: list[str] = json.loads(roles_raw) if roles_raw else []
        return Approval(
            id=int(row["id"]),
            ts=str(row["ts"]),
            session_id=str(row["session_id"]),
            principal_id=str(row["principal_id"]),
            principal_roles=roles,
            resource_kind=str(row["resource_kind"]),
            resource_id=str(row["resource_id"]),
            action=str(row["action"]),
            decision=str(row["decision"]),
            args_json=row["args_json"],
            cerbos_reason=row["cerbos_reason"],
            duration_ms=row["duration_ms"],
        )


__all__ = ["Approval", "Store"]

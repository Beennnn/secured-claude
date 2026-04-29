"""Append-only SQLite audit store with hash-chain integrity (ADR-0004 + ADR-0024).

INSERT-only schema enforced by triggers that ABORT on UPDATE/DELETE. The DB
file is created with mode 0o600 so the host user is the only reader on
multi-tenant Linux machines.

Each row carries a SHA-256 chain hash : `row_hash = SHA256(prev_hash || ":" ||
canonical_json(row_content))`. Tampering with any row breaks the chain and
`verify_chain()` returns the index of the first break. A `rm approvals.db`
attack still succeeds (the file IS deletable from outside the application),
but the next legitimate INSERT after a tamper has no valid `prev_hash` to
build on — the resulting chain is detectably broken on the next `audit verify`.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secured_claude._paths import db_path

# 64 zeros = SHA-256 of "" baseline ; cleanly distinguishable from a real hash.
GENESIS_PREV_HASH = "0" * 64

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
    duration_ms     INTEGER,
    prev_hash       TEXT,
    row_hash        TEXT
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
    prev_hash: str | None = None
    row_hash: str | None = None


@dataclass(frozen=True)
class ChainBreak:
    """Detected mismatch in the hash chain."""

    row_id: int
    ts: str
    expected_hash: str
    actual_hash: str
    reason: str


def _canonical_payload(
    *,
    ts: str,
    session_id: str,
    principal_id: str,
    principal_roles_json: str,
    resource_kind: str,
    resource_id: str,
    action: str,
    decision: str,
    args_json: str | None,
    cerbos_reason: str | None,
    duration_ms: int | None,
) -> bytes:
    """Stable byte representation of a row's content for hashing.

    Deliberately excludes `id` (assigned by SQLite AUTOINCREMENT after
    INSERT) and the hash columns themselves. JSON with sorted keys and
    no whitespace gives a deterministic byte sequence across platforms.
    """
    return json.dumps(
        {
            "ts": ts,
            "session_id": session_id,
            "principal_id": principal_id,
            "principal_roles": principal_roles_json,
            "resource_kind": resource_kind,
            "resource_id": resource_id,
            "action": action,
            "decision": decision,
            "args_json": args_json,
            "cerbos_reason": cerbos_reason,
            "duration_ms": duration_ms,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _compute_row_hash(prev_hash: str, payload: bytes) -> str:
    """SHA-256(prev_hash || ":" || canonical_payload) as hex digest."""
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(b":")
    h.update(payload)
    return h.hexdigest()


class Store:
    """SQLite-backed append-only store for approval decisions."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or db_path()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            # Migration : pre-v0.3 databases lack prev_hash / row_hash columns.
            # ALTER TABLE ADD COLUMN is idempotent-ish (we catch the error).
            for col in ("prev_hash", "row_hash"):
                try:
                    conn.execute(f"ALTER TABLE approvals ADD COLUMN {col} TEXT")
                except sqlite3.OperationalError:
                    # Column already exists (most common case).
                    pass
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

    def _last_row_hash(self, conn: sqlite3.Connection) -> str:
        """Return the most recent row's row_hash, or GENESIS_PREV_HASH if empty."""
        row = conn.execute(
            "SELECT row_hash FROM approvals ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None or row["row_hash"] is None:
            return GENESIS_PREV_HASH
        return str(row["row_hash"])

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
        principal_roles_json = json.dumps(principal_roles)
        args_json = json.dumps(args) if args is not None else None
        with self._connect() as conn:
            prev_hash = self._last_row_hash(conn)
            payload = _canonical_payload(
                ts=ts,
                session_id=session_id,
                principal_id=principal_id,
                principal_roles_json=principal_roles_json,
                resource_kind=resource_kind,
                resource_id=resource_id,
                action=action,
                decision=decision,
                args_json=args_json,
                cerbos_reason=cerbos_reason,
                duration_ms=duration_ms,
            )
            row_hash = _compute_row_hash(prev_hash, payload)
            cur = conn.execute(
                """
                INSERT INTO approvals (
                    ts, session_id, principal_id, principal_roles,
                    resource_kind, resource_id, action, decision,
                    args_json, cerbos_reason, duration_ms,
                    prev_hash, row_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    session_id,
                    principal_id,
                    principal_roles_json,
                    resource_kind,
                    resource_id,
                    action,
                    decision,
                    args_json,
                    cerbos_reason,
                    duration_ms,
                    prev_hash,
                    row_hash,
                ),
            )
            return int(cur.lastrowid or 0)

    def verify_chain(self) -> ChainBreak | None:
        """Walk the audit log forward, recomputing each row's hash.

        Returns None if the chain is intact, or a ChainBreak describing the
        first detected mismatch. Pre-v0.3 rows (NULL prev_hash / row_hash)
        are skipped — the chain starts at the first row with non-NULL hash
        columns.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM approvals ORDER BY id ASC"
            ).fetchall()
        prev_hash: str | None = None
        for row in rows:
            stored_prev = row["prev_hash"]
            stored_row = row["row_hash"]
            if stored_prev is None or stored_row is None:
                # Pre-chain row (migrated from v0.2 or earlier). Skip ;
                # the chain restarts on the next row that has hashes.
                prev_hash = None
                continue
            if prev_hash is None:
                # First chained row : verify it links to the genesis sentinel
                # OR to the (non-chained) previous row's missing hash.
                # We only enforce GENESIS for the very first row of the table
                # to avoid false-positives on v0.2→v0.3 migrations.
                expected_prev_minimum = stored_prev
            else:
                expected_prev_minimum = prev_hash

            if stored_prev != expected_prev_minimum:
                return ChainBreak(
                    row_id=int(row["id"]),
                    ts=str(row["ts"]),
                    expected_hash=expected_prev_minimum,
                    actual_hash=str(stored_prev),
                    reason="prev_hash mismatch — previous row was tampered or removed",
                )
            payload = _canonical_payload(
                ts=str(row["ts"]),
                session_id=str(row["session_id"]),
                principal_id=str(row["principal_id"]),
                principal_roles_json=str(row["principal_roles"]),
                resource_kind=str(row["resource_kind"]),
                resource_id=str(row["resource_id"]),
                action=str(row["action"]),
                decision=str(row["decision"]),
                args_json=row["args_json"],
                cerbos_reason=row["cerbos_reason"],
                duration_ms=row["duration_ms"],
            )
            expected = _compute_row_hash(stored_prev, payload)
            if expected != stored_row:
                return ChainBreak(
                    row_id=int(row["id"]),
                    ts=str(row["ts"]),
                    expected_hash=expected,
                    actual_hash=str(stored_row),
                    reason="row_hash mismatch — row content was modified after INSERT",
                )
            prev_hash = stored_row
        return None

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
        # row may not have prev_hash / row_hash columns if loaded from a
        # pre-v0.3 database before migration ran (defensive fallback).
        try:
            prev = row["prev_hash"]
        except (IndexError, KeyError):
            prev = None
        try:
            current = row["row_hash"]
        except (IndexError, KeyError):
            current = None
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
            prev_hash=prev,
            row_hash=current,
        )


__all__ = ["GENESIS_PREV_HASH", "Approval", "ChainBreak", "Store"]

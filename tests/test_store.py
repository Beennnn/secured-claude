"""Tests for the SQLite append-only audit store (ADR-0004 + ADR-0024 hash chain)."""

from __future__ import annotations

import sqlite3

import pytest

from secured_claude.store import GENESIS_PREV_HASH, Store


def test_insert_and_query(tmp_store: Store) -> None:
    rid = tmp_store.insert(
        session_id="s1",
        principal_id="claude-code-default",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/workspace/foo.py",
        action="read",
        decision="ALLOW",
        args={"path": "/workspace/foo.py"},
        cerbos_reason="effect=EFFECT_ALLOW",
        duration_ms=5,
    )
    assert rid > 0
    rows = tmp_store.query()
    assert len(rows) == 1
    row = rows[0]
    assert row.decision == "ALLOW"
    assert row.principal_roles == ["agent"]
    assert row.resource_kind == "file"
    assert row.resource_id == "/workspace/foo.py"
    assert row.cerbos_reason == "effect=EFFECT_ALLOW"
    assert row.duration_ms == 5


def test_invalid_decision_rejected(tmp_store: Store) -> None:
    with pytest.raises(ValueError, match="decision must be ALLOW or DENY"):
        tmp_store.insert(
            session_id="s1",
            principal_id="p",
            principal_roles=["agent"],
            resource_kind="file",
            resource_id="/x",
            action="read",
            decision="MAYBE",
        )


def test_append_only_blocks_update(tmp_store: Store) -> None:
    """The trigger refuses UPDATE on the approvals table (ADR-0004)."""
    tmp_store.insert(
        session_id="s1",
        principal_id="p",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/x",
        action="read",
        decision="ALLOW",
    )
    with tmp_store._connect() as conn:
        with pytest.raises(sqlite3.IntegrityError, match="append-only: UPDATE forbidden"):
            conn.execute("UPDATE approvals SET decision='DENY' WHERE id=1")


def test_append_only_blocks_delete(tmp_store: Store) -> None:
    """The trigger refuses DELETE on the approvals table (ADR-0004)."""
    tmp_store.insert(
        session_id="s1",
        principal_id="p",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/x",
        action="read",
        decision="ALLOW",
    )
    with tmp_store._connect() as conn:
        with pytest.raises(sqlite3.IntegrityError, match="append-only: DELETE forbidden"):
            conn.execute("DELETE FROM approvals WHERE id=1")


def test_filter_by_decision(tmp_store: Store) -> None:
    decisions = ["ALLOW", "DENY", "ALLOW", "DENY", "ALLOW"]
    for i, dec in enumerate(decisions):
        tmp_store.insert(
            session_id="s1",
            principal_id="p",
            principal_roles=["agent"],
            resource_kind="file",
            resource_id=f"/x{i}",
            action="read",
            decision=dec,
        )
    assert len(tmp_store.query(decision="ALLOW")) == 3
    assert len(tmp_store.query(decision="DENY")) == 2
    assert tmp_store.count() == 5


def test_filter_by_resource_kind(tmp_store: Store) -> None:
    tmp_store.insert(
        session_id="s1",
        principal_id="p",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/x",
        action="read",
        decision="ALLOW",
    )
    tmp_store.insert(
        session_id="s1",
        principal_id="p",
        principal_roles=["agent"],
        resource_kind="command",
        resource_id="git",
        action="execute",
        decision="ALLOW",
    )
    files = tmp_store.query(resource_kind="file")
    cmds = tmp_store.query(resource_kind="command")
    assert len(files) == 1
    assert len(cmds) == 1
    assert files[0].resource_kind == "file"
    assert cmds[0].resource_kind == "command"


# ────────────────────────────────────────────────────────────────────
# ADR-0024 — hash chain integrity
# ────────────────────────────────────────────────────────────────────


def _seed(store: Store, n: int = 3) -> list[int]:
    ids = []
    for i in range(n):
        ids.append(
            store.insert(
                session_id="s1",
                principal_id="p",
                principal_roles=["agent"],
                resource_kind="file",
                resource_id=f"/x{i}",
                action="read",
                decision="ALLOW",
            )
        )
    return ids


def test_first_row_links_to_genesis(tmp_store: Store) -> None:
    """The first inserted row's prev_hash equals the genesis sentinel."""
    _seed(tmp_store, n=1)
    rows = tmp_store.query(limit=10)
    assert rows[0].prev_hash == GENESIS_PREV_HASH
    assert rows[0].row_hash is not None
    assert len(rows[0].row_hash) == 64  # SHA-256 hex


def test_subsequent_rows_link_to_previous(tmp_store: Store) -> None:
    """Each row's prev_hash equals the previous row's row_hash."""
    _seed(tmp_store, n=3)
    rows = sorted(tmp_store.query(limit=10), key=lambda r: r.id)
    assert rows[0].prev_hash == GENESIS_PREV_HASH
    assert rows[1].prev_hash == rows[0].row_hash
    assert rows[2].prev_hash == rows[1].row_hash


def test_verify_chain_returns_none_when_intact(tmp_store: Store) -> None:
    _seed(tmp_store, n=5)
    assert tmp_store.verify_chain() is None


def test_verify_chain_detects_row_content_tampering(tmp_store: Store) -> None:
    """Modifying a stored field directly via SQL bypasses the trigger by
    using a fresh connection that doesn't carry the trigger state — but
    the recomputed row_hash no longer matches, so verify_chain detects it.

    In practice the trigger DOES block UPDATE (test_append_only_blocks_update),
    but a malicious SQLite tool could rewrite the file at byte level. The
    chain is the second line of defence : it makes such tampering visible.
    """
    _seed(tmp_store, n=3)
    # Bypass the trigger by dropping it and tampering — simulates a raw
    # byte-level edit by an external process.
    with tmp_store._connect() as conn:
        conn.execute("DROP TRIGGER approvals_no_update")
        conn.execute("UPDATE approvals SET decision='DENY' WHERE id=2")
    chain_break = tmp_store.verify_chain()
    assert chain_break is not None
    assert chain_break.row_id == 2
    assert "row_hash mismatch" in chain_break.reason


def test_verify_chain_detects_prev_hash_tampering(tmp_store: Store) -> None:
    """Rewriting prev_hash to a different valid-looking value also breaks
    the chain (the row_hash recomputation will be wrong vs stored)."""
    _seed(tmp_store, n=3)
    with tmp_store._connect() as conn:
        conn.execute("DROP TRIGGER approvals_no_update")
        conn.execute("UPDATE approvals SET prev_hash=? WHERE id=2", ("a" * 64,))
    chain_break = tmp_store.verify_chain()
    assert chain_break is not None
    assert chain_break.row_id == 2
    # Either the prev_hash mismatch or the recomputed row_hash mismatch will trigger.
    assert "mismatch" in chain_break.reason


def test_verify_chain_handles_pre_v03_rows(tmp_store: Store) -> None:
    """Rows inserted before the hash columns existed have NULL prev/row_hash.
    verify_chain skips them (chain restarts at first row with hash columns)."""
    # Insert 2 normal rows.
    _seed(tmp_store, n=2)
    # Forge a "pre-v0.3" row by clearing its hash columns directly.
    with tmp_store._connect() as conn:
        conn.execute("DROP TRIGGER approvals_no_update")
        conn.execute("UPDATE approvals SET prev_hash=NULL, row_hash=NULL WHERE id=1")
        # Re-create trigger so the test's other assertions still hold.
        conn.execute(
            """
            CREATE TRIGGER approvals_no_update BEFORE UPDATE ON approvals
            BEGIN SELECT RAISE(ABORT, 'append-only: UPDATE forbidden'); END
            """
        )
    # Insert a fresh row — its prev_hash should link to row 2's row_hash.
    _seed(tmp_store, n=1)
    # verify_chain should still pass — it skips the NULL-hash row.
    assert tmp_store.verify_chain() is None

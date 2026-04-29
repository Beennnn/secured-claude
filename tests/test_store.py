"""Tests for the SQLite append-only audit store (ADR-0004)."""

from __future__ import annotations

import sqlite3

import pytest

from secured_claude.store import Store


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

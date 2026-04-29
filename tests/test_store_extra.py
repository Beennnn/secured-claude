"""Extra store tests — query filters and edge cases for higher coverage."""

from __future__ import annotations

from secured_claude.store import Store


def test_filter_by_principal_id(tmp_store: Store) -> None:
    tmp_store.insert(
        session_id="s",
        principal_id="alice",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/x",
        action="read",
        decision="ALLOW",
    )
    tmp_store.insert(
        session_id="s",
        principal_id="bob",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/y",
        action="read",
        decision="ALLOW",
    )
    assert len(tmp_store.query(principal_id="alice")) == 1
    assert len(tmp_store.query(principal_id="bob")) == 1
    assert len(tmp_store.query(principal_id="charlie")) == 0


def test_filter_by_action(tmp_store: Store) -> None:
    for act in ["read", "write", "edit", "read"]:
        tmp_store.insert(
            session_id="s",
            principal_id="p",
            principal_roles=["agent"],
            resource_kind="file",
            resource_id="/x",
            action=act,
            decision="ALLOW",
        )
    assert len(tmp_store.query(action="read")) == 2
    assert len(tmp_store.query(action="write")) == 1
    assert len(tmp_store.query(action="edit")) == 1


def test_filter_by_since_iso_timestamp(tmp_store: Store) -> None:
    """`since` is a string-comparable ISO 8601 timestamp ; future date returns nothing."""
    tmp_store.insert(
        session_id="s",
        principal_id="p",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/x",
        action="read",
        decision="ALLOW",
    )
    # 'since' in the future returns no rows
    assert len(tmp_store.query(since="2099-01-01T00:00:00.000+00:00")) == 0
    # 'since' in the past returns the row
    assert len(tmp_store.query(since="2020-01-01T00:00:00.000+00:00")) == 1


def test_query_limit_caps_results(tmp_store: Store) -> None:
    for i in range(5):
        tmp_store.insert(
            session_id="s",
            principal_id="p",
            principal_roles=["agent"],
            resource_kind="file",
            resource_id=f"/x{i}",
            action="read",
            decision="ALLOW",
        )
    assert len(tmp_store.query(limit=3)) == 3
    assert len(tmp_store.query(limit=100)) == 5


def test_count_returns_total(tmp_store: Store) -> None:
    assert tmp_store.count() == 0
    for _ in range(3):
        tmp_store.insert(
            session_id="s",
            principal_id="p",
            principal_roles=["agent"],
            resource_kind="file",
            resource_id="/x",
            action="read",
            decision="ALLOW",
        )
    assert tmp_store.count() == 3


def test_args_none_stored_as_null(tmp_store: Store) -> None:
    tmp_store.insert(
        session_id="s",
        principal_id="p",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/x",
        action="read",
        decision="ALLOW",
        args=None,
    )
    rows = tmp_store.query()
    assert rows[0].args_json is None

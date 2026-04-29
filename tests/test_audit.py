"""Tests for the audit query/format helpers (no Cerbos / no Docker needed)."""

from __future__ import annotations

import io
import json

from rich.console import Console

from secured_claude import audit
from secured_claude.store import Approval, Store


def _row(decision: str = "ALLOW") -> Approval:
    return Approval(
        id=1,
        ts="2026-04-29T06:42:13.000+00:00",
        session_id="s1",
        principal_id="claude-code-default",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/workspace/foo.py",
        action="read",
        decision=decision,
        args_json='{"path": "/workspace/foo.py"}',
        cerbos_reason="effect=EFFECT_ALLOW",
        duration_ms=4,
    )


def test_render_table_with_rows() -> None:
    buf = io.StringIO()
    cons = Console(file=buf, width=200, force_terminal=False, color_system=None)
    audit.render_table([_row("ALLOW"), _row("DENY")], console=cons)
    text = buf.getvalue()
    assert "ALLOW" in text
    assert "DENY" in text
    assert "/workspace/foo.py" in text


def test_render_table_empty() -> None:
    buf = io.StringIO()
    cons = Console(file=buf, width=200, force_terminal=False, color_system=None)
    audit.render_table([], console=cons)
    assert "No matching audit rows" in buf.getvalue()


def test_render_json_one_row_per_line() -> None:
    rows = [_row("ALLOW"), _row("DENY")]
    out = audit.render_json(rows)
    lines = out.split("\n")
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["decision"] == "ALLOW"
    assert parsed[1]["decision"] == "DENY"
    assert parsed[0]["resource_id"] == "/workspace/foo.py"


def test_query_passes_filters_through(tmp_path) -> None:
    store = Store(path=tmp_path / "test.db")
    store.insert(
        session_id="s",
        principal_id="alice",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/x",
        action="read",
        decision="ALLOW",
    )
    store.insert(
        session_id="s",
        principal_id="bob",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/y",
        action="read",
        decision="DENY",
    )
    rows = audit.query(store, decision="DENY")
    assert len(rows) == 1
    assert rows[0].principal_id == "bob"

    rows = audit.query(store, principal_id="alice", limit=10)
    assert len(rows) == 1
    assert rows[0].decision == "ALLOW"

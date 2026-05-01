"""Tests for the audit query/format helpers (no Cerbos / no Docker needed)."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta

import pytest
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


# ────────────────────────────────────────────────────────────────────
# parse_since — relative duration + ISO 8601 + error path
# ────────────────────────────────────────────────────────────────────


def test_parse_since_relative_minutes_returns_iso_in_past() -> None:
    """`5m` → ISO 8601 ts dated ~5 minutes ago, milliseconds + tz offset."""
    before = datetime.now(UTC)
    result = audit.parse_since("5m")
    after = datetime.now(UTC)
    parsed = datetime.fromisoformat(result)
    expected_min = before - timedelta(minutes=5, seconds=1)
    expected_max = after - timedelta(minutes=5) + timedelta(seconds=1)
    assert expected_min <= parsed <= expected_max


@pytest.mark.parametrize(
    ("since", "expected_unit", "n"),
    [
        ("30s", "seconds", 30),
        ("2h", "hours", 2),
        ("1d", "days", 1),
        ("1w", "weeks", 1),
    ],
)
def test_parse_since_relative_all_units(since: str, expected_unit: str, n: int) -> None:
    delta = timedelta(**{expected_unit: n})
    expected = datetime.now(UTC) - delta
    parsed = datetime.fromisoformat(audit.parse_since(since))
    # within 2 s of now-delta — covers any clock drift during the test
    assert abs((parsed - expected).total_seconds()) < 2


def test_parse_since_iso8601_passthrough() -> None:
    iso = "2026-05-01T10:00:00+00:00"
    assert audit.parse_since(iso) == iso


def test_parse_since_iso8601_with_z_passthrough() -> None:
    # `2026-...` is treated as ISO and passed through verbatim ;
    # SQLite's lexicographic comparison handles `Z` and `+00:00` equivalently.
    iso = "2026-05-01T10:00:00Z"
    assert audit.parse_since(iso) == iso


def test_parse_since_invalid_format_raises() -> None:
    with pytest.raises(ValueError, match="unrecognized format"):
        audit.parse_since("not-a-thing")


def test_parse_since_strips_whitespace() -> None:
    parsed = datetime.fromisoformat(audit.parse_since("  5m  "))
    expected = datetime.now(UTC) - timedelta(minutes=5)
    assert abs((parsed - expected).total_seconds()) < 2


def test_query_applies_parse_since(tmp_path) -> None:
    """Integration : query() routes `since` through parse_since (so a relative
    value reaches Store.query as ISO 8601, not as raw '5m')."""
    store = Store(path=tmp_path / "test.db")
    # Insert one row via the regular API (timestamped 'now').
    store.insert(
        session_id="s",
        principal_id="p",
        principal_roles=["agent"],
        resource_kind="file",
        resource_id="/fresh",
        action="read",
        decision="ALLOW",
    )
    # Insert one stale row via raw SQL — bypasses store.insert's
    # auto-`now()` timestamp. Triggers only block UPDATE/DELETE, not INSERT.
    stale_ts = "2020-01-01T00:00:00.000+00:00"
    with store._connect() as conn:
        conn.execute(
            "INSERT INTO approvals (ts, session_id, principal_id, principal_roles, "
            "resource_kind, resource_id, action, decision) "
            "VALUES (?, 's', 'p', '[]', 'file', '/stale', 'read', 'ALLOW')",
            (stale_ts,),
        )
    rows = audit.query(store, since="5m")
    rids = {r.resource_id for r in rows}
    assert "/fresh" in rids
    assert "/stale" not in rids

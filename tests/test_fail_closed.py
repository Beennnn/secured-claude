"""Tests for ADR-0009: gateway fails closed when Cerbos is unreachable."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from secured_claude.gateway import make_app
from secured_claude.store import Store


def test_gateway_denies_when_cerbos_raises_connection_error(tmp_path: Path) -> None:
    """Cerbos client raises ConnectionError → gateway returns approve=False (DENY) and logs."""
    cerbos = MagicMock()
    cerbos.check.side_effect = ConnectionError("Cerbos PDP not reachable")
    store = Store(path=tmp_path / "test.db")
    client = TestClient(make_app(cerbos=cerbos, store=store))

    resp = client.post(
        "/check",
        json={"tool": "Read", "tool_input": {"file_path": "/workspace/x"}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approve"] is False
    assert "cerbos PDP unavailable" in body["reason"]
    assert "ConnectionError" in body["reason"]
    rows = store.query()
    assert len(rows) == 1
    assert rows[0].decision == "DENY"


def test_gateway_denies_on_arbitrary_exception(tmp_path: Path) -> None:
    """Any unhandled exception → DENY (fail-closed posture, ADR-0009)."""
    cerbos = MagicMock()
    cerbos.check.side_effect = RuntimeError("kaboom")
    store = Store(path=tmp_path / "test.db")
    client = TestClient(make_app(cerbos=cerbos, store=store))

    resp = client.post(
        "/check",
        json={"tool": "Bash", "tool_input": {"command": "ls"}},
    )
    body = resp.json()
    assert body["approve"] is False
    assert "RuntimeError" in body["reason"]

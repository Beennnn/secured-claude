"""Tests for the FastAPI gateway (ADR-0001, ADR-0004)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from secured_claude.cerbos_client import CheckResult
from secured_claude.gateway import make_app, map_tool_to_resource
from secured_claude.store import Store


def _make_app(tmp_path: Path, *, allow: bool) -> tuple[TestClient, Store]:
    cerbos = MagicMock()
    cerbos.check.return_value = CheckResult(
        allow=allow,
        reason=f"effect={'EFFECT_ALLOW' if allow else 'EFFECT_DENY'}",
        duration_ms=3,
        raw={},
    )
    store = Store(path=tmp_path / "test.db")
    app = make_app(cerbos=cerbos, store=store)
    return TestClient(app), store


def test_check_allow_logs_to_store(tmp_path: Path) -> None:
    client, store = _make_app(tmp_path, allow=True)
    resp = client.post(
        "/check",
        json={
            "tool": "Read",
            "tool_input": {"file_path": "/workspace/foo.py"},
            "principal_id": "claude-code-default",
            "session_id": "s1",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approve"] is True
    assert store.count() == 1
    rows = store.query()
    assert rows[0].decision == "ALLOW"
    assert rows[0].resource_kind == "file"
    assert rows[0].action == "read"
    assert rows[0].session_id == "s1"


def test_check_deny_logs_to_store(tmp_path: Path) -> None:
    client, store = _make_app(tmp_path, allow=False)
    resp = client.post(
        "/check",
        json={"tool": "Read", "tool_input": {"file_path": "/etc/passwd"}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approve"] is False
    rows = store.query()
    assert rows[0].decision == "DENY"


def test_health_endpoint(tmp_path: Path) -> None:
    client, _ = _make_app(tmp_path, allow=True)
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["approvals_count"] == 0


def test_map_read_extracts_path() -> None:
    kind, _rid, action, attr = map_tool_to_resource("Read", {"file_path": "/workspace/foo.py"})
    assert kind == "file"
    assert action == "read"
    assert attr["path"] == "/workspace/foo.py"


def test_map_bash_extracts_first_word() -> None:
    kind, _rid, action, attr = map_tool_to_resource("Bash", {"command": "git status --short"})
    assert kind == "command"
    assert action == "execute"
    assert attr["cmd_first_word"] == "git"
    assert attr["full_cmd"] == "git status --short"


def test_map_webfetch_extracts_host_and_scheme() -> None:
    kind, _rid, action, attr = map_tool_to_resource(
        "WebFetch", {"url": "https://api.anthropic.com/v1/messages"}
    )
    assert kind == "url"
    assert action == "fetch"
    assert attr["host"] == "api.anthropic.com"
    assert attr["scheme"] == "https"
    assert attr["port"] == 443


def test_map_mcp_tool_parses_server_and_tool() -> None:
    kind, _rid, action, attr = map_tool_to_resource("mcp__iris-service-java__get_health", {})
    assert kind == "mcp_tool"
    assert action == "invoke"
    assert attr["server"] == "iris-service-java"
    assert attr["tool"] == "get_health"


def test_map_unknown_tool_falls_back() -> None:
    kind, _rid, action, _attr = map_tool_to_resource("FrobnicateXYZ", {"a": 1})
    assert kind == "unknown_tool"
    assert action == "invoke"

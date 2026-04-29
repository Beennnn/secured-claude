"""In-process hook tests — direct call to `hook.main()` so coverage tracks them.

These complement `test_hook_format.py` (which spawns a real subprocess and
verifies the JSON contract end-to-end) by exercising the same code path
without process boundaries, raising the coverage of `hook.py`.

We use pytest's `capsys` fixture for stdout (works even when production code
calls `sys.exit`) and `monkeypatch.setattr("sys.stdin", ...)` for stdin —
this is the idiomatic pytest pattern, more robust than `unittest.mock.patch`.
"""

from __future__ import annotations

import io
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests

from secured_claude import hook


def _read_decision(captured_out: str) -> dict[str, Any]:
    """Pull the JSON decision back out of pytest-captured stdout."""
    line = captured_out.strip().split("\n")[-1]
    parsed: dict[str, Any] = json.loads(line)
    return parsed


def test_hook_allow_when_broker_approves(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = json.dumps(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": "/workspace/foo.py"},
            "session_id": "s1",
        }
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    monkeypatch.setenv("SECURED_CLAUDE_BROKER", "http://example.invalid:8765")

    fake_resp = MagicMock()
    fake_resp.json.return_value = {"approve": True, "reason": "effect=EFFECT_ALLOW"}
    fake_resp.raise_for_status = MagicMock()
    monkeypatch.setattr("secured_claude.hook.requests.post", lambda *a, **kw: fake_resp)

    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 0
    decision = _read_decision(capsys.readouterr().out)
    assert decision["permissionDecision"] == "allow"


def test_hook_deny_when_broker_returns_approve_false(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/etc/passwd"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    monkeypatch.setenv("SECURED_CLAUDE_BROKER", "http://example.invalid:8765")

    fake_resp = MagicMock()
    fake_resp.json.return_value = {
        "approve": False,
        "reason": "effect=EFFECT_DENY; path matches deny pattern",
    }
    fake_resp.raise_for_status = MagicMock()
    monkeypatch.setattr("secured_claude.hook.requests.post", lambda *a, **kw: fake_resp)

    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 2
    decision = _read_decision(capsys.readouterr().out)
    assert decision["permissionDecision"] == "deny"
    assert "deny pattern" in decision["permissionDecisionReason"]


def test_hook_deny_on_request_exception(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ADR-0009: hook fails closed when the broker request raises."""
    payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/x"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    monkeypatch.setenv("SECURED_CLAUDE_BROKER", "http://example.invalid:8765")

    def _raise(*_a: object, **_kw: object) -> None:
        raise requests.ConnectionError("nope")

    monkeypatch.setattr("secured_claude.hook.requests.post", _raise)

    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 2
    decision = _read_decision(capsys.readouterr().out)
    assert decision["permissionDecision"] == "deny"
    assert "broker unavailable" in decision["permissionDecisionReason"]


def test_hook_deny_on_invalid_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("not-json{"))
    monkeypatch.setenv("SECURED_CLAUDE_BROKER", "http://example.invalid:8765")

    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 2
    decision = _read_decision(capsys.readouterr().out)
    assert decision["permissionDecision"] == "deny"
    assert "invalid stdin JSON" in decision["permissionDecisionReason"]


def test_hook_empty_stdin_falls_through_to_broker(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Empty stdin → empty dict → tool='unknown' → broker still consulted."""
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    monkeypatch.setenv("SECURED_CLAUDE_BROKER", "http://example.invalid:8765")

    def _raise(*_a: object, **_kw: object) -> None:
        raise requests.ConnectionError("unreachable")

    monkeypatch.setattr("secured_claude.hook.requests.post", _raise)

    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 2
    decision = _read_decision(capsys.readouterr().out)
    assert decision["permissionDecision"] == "deny"

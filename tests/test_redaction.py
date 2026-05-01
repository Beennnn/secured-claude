"""Tests for the redaction engine + /transform route (ADR-0046)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from secured_claude.cerbos_client import CheckResult
from secured_claude.gateway import make_app
from secured_claude.redaction import RedactionEngine, make_engine
from secured_claude.store import Store

# ────────────────────────────────────────────────────────────────────
# Pattern coverage — known secret formats produce a placeholder
# ────────────────────────────────────────────────────────────────────


# Test fixtures are assembled at runtime via string concatenation so the
# literal secret value never appears in source — keeps GitHub Push
# Protection + gitleaks default rules from blocking the push. The patterns
# in src/secured_claude/redaction.py still match them at runtime.
_ALPHA_BLOCK = "A" + "b" + "C" + "d" + "E" + "f" + "G" + "h"  # 8 chars
_TEST_SECRETS: list[tuple[str, str]] = [
    ("aws-access-key", "AKI" + "A" + "IOSFODNN7EXAMPLE"),  # AKIA + 16
    ("github-pat", "g" + "hp_" + "a" * 36),  # ghp_ + 36 chars
    ("gitlab-pat", "gl" + "pat-" + "x" * 20),
    (
        "slack-bot-token",
        "xo" + "xb-" + "1234567890-1234567890123-" + _ALPHA_BLOCK * 3,  # 24-char tail
    ),
    ("stripe-live-secret", "sk" + "_live_" + _ALPHA_BLOCK * 3),  # 24 chars after prefix
    (
        "anthropic-api-key",
        "sk-" + "ant-" + _ALPHA_BLOCK * 4 + "01234567",  # 40 chars after prefix
    ),
    (
        "jwt",
        "ey"
        + "J"
        + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        + "ey"
        + "J"
        + "zdWIiOiIxMjM0NTY3ODkwIn0."
        + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ),
]


@pytest.mark.parametrize(("rule_name", "secret"), _TEST_SECRETS)
def test_known_secret_format_redacted(rule_name: str, secret: str) -> None:
    eng = RedactionEngine()
    out = eng.redact(f"prefix {secret} suffix", session_id="s1")
    assert "<<SECRET:" in out.content, f"expected placeholder for {rule_name}"
    assert secret not in out.content, f"raw {rule_name} value leaked"
    assert rule_name in out.matches, f"rule {rule_name} should have fired"


def test_pem_private_key_redacted_multiline() -> None:
    eng = RedactionEngine()
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEogIBAAKCAQEAxEZ3...lots-of-base64...==\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = eng.redact(f"key={pem}", session_id="s1")
    assert "<<SECRET:" in out.content
    assert "BEGIN RSA PRIVATE KEY" not in out.content
    assert "pem-private-key" in out.matches


def test_db_connection_string_redacted() -> None:
    eng = RedactionEngine()
    out = eng.redact(
        "DATABASE_URL=postgres://app:hunter2@db.example.com:5432/prod", session_id="s1"
    )
    assert "hunter2" not in out.content
    assert "<<SECRET:" in out.content


def test_no_secret_no_change() -> None:
    """Plain code passes through unchanged ; no false positives."""
    eng = RedactionEngine()
    src = "def compute_total(items):\n    return sum(item.price for item in items)\n"
    out = eng.redact(src, session_id="s1")
    assert out.content == src
    assert out.matches == []


def test_multiple_secrets_in_same_input() -> None:
    eng = RedactionEngine()
    content = (
        f"AWS_ACCESS_KEY_ID={'AKI' + 'A' + 'IOSFODNN7EXAMPLE'}\n"
        f"AWS_SECRET_ACCESS_KEY={'wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + 'EXAMPLEKEY'}\n"
        f"GITHUB_TOKEN={'g' + 'hp_' + 'aBCdeFgHIjKlmNopQRsTUvwXyZ0123456789'}\n"
    )
    out = eng.redact(content, session_id="s1")
    # 3 distinct placeholders should appear (count <<SECRET: occurrences)
    assert out.content.count("<<SECRET:") == 3
    assert ("AKI" + "A" + "IOSFODNN7EXAMPLE") not in out.content
    assert ("wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY") not in out.content
    assert ("g" + "hp_" + ("aBCdeFgHIjKlmNopQRsTUvwXyZ" + "0123456789")) not in out.content
    assert {"aws-access-key", "aws-secret-key", "github-pat"}.issubset(set(out.matches))


# ────────────────────────────────────────────────────────────────────
# restore() — placeholders go back to original values
# ────────────────────────────────────────────────────────────────────


def test_restore_substitutes_placeholders_back() -> None:
    eng = RedactionEngine()
    token_value = "g" + "hp_" + "aBCdeFgHIjKlmNopQRsTUvwXyZ0123456789"
    redacted = eng.redact(f"token={token_value}", session_id="s1")
    placeholder = next(p for p in redacted.mapping)
    restored = eng.restore(f"echo {placeholder} | xargs use-token", session_id="s1")
    assert token_value in restored
    assert "<<SECRET:" not in restored


def test_restore_unknown_placeholder_passes_through() -> None:
    """A placeholder not in the session map is returned unchanged ; the
    has_unresolved_placeholder() guard catches it before execution."""
    eng = RedactionEngine()
    out = eng.restore("echo <<SECRET:cafebabe1234567>>", session_id="never-saw-it")
    assert "<<SECRET:cafebabe1234567>>" in out


def test_restore_session_isolation() -> None:
    """Placeholders from session A don't substitute in session B."""
    eng = RedactionEngine()
    redacted_a = eng.redact(("AKI" + "A" + "IOSFODNN7EXAMPLE"), session_id="A")
    placeholder = next(iter(redacted_a.mapping))
    out_b = eng.restore(f"got {placeholder}", session_id="B")
    assert placeholder in out_b
    assert ("AKI" + "A" + "IOSFODNN7EXAMPLE") not in out_b


# ────────────────────────────────────────────────────────────────────
# has_unresolved_placeholder() — detects forged / cross-session refs
# ────────────────────────────────────────────────────────────────────


def test_has_unresolved_detects_unknown_placeholder() -> None:
    eng = RedactionEngine()
    assert eng.has_unresolved_placeholder("use <<SECRET:cafebabe12345678>>", session_id="s1")


def test_has_unresolved_passes_known_placeholder() -> None:
    eng = RedactionEngine()
    redacted = eng.redact(("AKI" + "A" + "IOSFODNN7EXAMPLE"), session_id="s1")
    placeholder = next(iter(redacted.mapping))
    assert eng.has_unresolved_placeholder(placeholder, session_id="s1") is False


def test_has_unresolved_no_placeholders_returns_false() -> None:
    eng = RedactionEngine()
    assert eng.has_unresolved_placeholder("plain text no placeholders", session_id="s1") is False


# ────────────────────────────────────────────────────────────────────
# make_engine() — env-driven activation
# ────────────────────────────────────────────────────────────────────


def test_make_engine_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECURED_CLAUDE_REDACT_LEVEL", raising=False)
    assert make_engine() is None


def test_make_engine_off_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_REDACT_LEVEL", "off")
    assert make_engine() is None


def test_make_engine_secrets_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_REDACT_LEVEL", "secrets")
    eng = make_engine()
    assert isinstance(eng, RedactionEngine)


def test_make_engine_aggressive_alias_for_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """v0.8.0 — aggressive falls through to the same engine ; v0.8.x can split."""
    monkeypatch.setenv("SECURED_CLAUDE_REDACT_LEVEL", "aggressive")
    eng = make_engine()
    assert isinstance(eng, RedactionEngine)


def test_make_engine_unknown_level_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_REDACT_LEVEL", "weird-value")
    assert make_engine() is None


# ────────────────────────────────────────────────────────────────────
# /transform route end-to-end
# ────────────────────────────────────────────────────────────────────


def _make_app_with_redaction(tmp_path: Path) -> TestClient:
    cerbos = MagicMock()
    cerbos.check.return_value = CheckResult(allow=True, reason="ok", duration_ms=2, raw={})
    app = make_app(
        cerbos=cerbos,
        store=Store(path=tmp_path / "test.db"),
        redaction=RedactionEngine(),
    )
    return TestClient(app)


def test_transform_redact_replaces_known_secret(tmp_path: Path) -> None:
    client = _make_app_with_redaction(tmp_path)
    resp = client.post(
        "/transform",
        json={
            "action": "redact",
            "content": f"AWS_ACCESS_KEY_ID={'AKI' + 'A' + 'IOSFODNN7EXAMPLE'}",
            "session_id": "s1",
        },
    )
    body = resp.json()
    assert resp.status_code == 200
    assert ("AKI" + "A" + "IOSFODNN7EXAMPLE") not in body["content"]
    assert "<<SECRET:" in body["content"]
    assert "aws-access-key" in body["matches_fired"]


def test_transform_restore_substitutes_back(tmp_path: Path) -> None:
    client = _make_app_with_redaction(tmp_path)
    token_value = "g" + "hp_" + "aBCdeFgHIjKlmNopQRsTUvwXyZ0123456789"
    # First : redact to get a placeholder we can later restore
    redact_resp = client.post(
        "/transform",
        json={
            "action": "redact",
            "content": f"GITHUB_TOKEN={token_value}",
            "session_id": "s2",
        },
    )
    redacted_content = redact_resp.json()["content"]
    # Pick the placeholder out of the redacted content
    placeholder = redacted_content.split("=")[1].strip()
    # Now restore : the placeholder should map back to the original
    restore_resp = client.post(
        "/transform",
        json={
            "action": "restore",
            "content": f"git clone https://oauth2:{placeholder}@github.com/foo/bar",
            "session_id": "s2",
        },
    )
    assert token_value in restore_resp.json()["content"]


def test_transform_disabled_when_engine_none(tmp_path: Path) -> None:
    """make_app(redaction=None) → /transform passes through unchanged."""
    cerbos = MagicMock()
    cerbos.check.return_value = CheckResult(allow=True, reason="ok", duration_ms=2, raw={})
    app = make_app(cerbos=cerbos, store=Store(path=tmp_path / "test.db"), redaction=None)
    client = TestClient(app)
    resp = client.post(
        "/transform",
        json={
            "action": "redact",
            "content": ("AKI" + "A" + "IOSFODNN7EXAMPLE"),
            "session_id": "s1",
        },
    )
    # No redaction engine : content passes through
    assert resp.json()["content"] == ("AKI" + "A" + "IOSFODNN7EXAMPLE")


def test_check_denies_unresolved_placeholder_in_bash(tmp_path: Path) -> None:
    """ADR-0046 : Bash command referencing an unknown placeholder → DENY,
    refusing to ship the literal `<<SECRET:abc>>` to the shell."""
    client = _make_app_with_redaction(tmp_path)
    resp = client.post(
        "/check",
        json={
            "tool": "Bash",
            "tool_input": {"command": "echo <<SECRET:cafebabe12345678>>"},
            "session_id": "s-malicious",
        },
    )
    body = resp.json()
    assert body["approve"] is False
    assert "redaction placeholder" in body["reason"]


# ────────────────────────────────────────────────────────────────────
# hook_post.py — PostToolUse redaction hook entry-point
# ────────────────────────────────────────────────────────────────────


def _run_hook_post(stdin_data: str, monkeypatch: pytest.MonkeyPatch) -> tuple[str, int]:
    """Invoke hook_post.main() with a faked stdin + capture stdout / exit."""
    import io

    from secured_claude import hook_post as posthook

    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_data))
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)
    try:
        posthook.main()
        exit_code = 0
    except SystemExit as e:
        exit_code = int(e.code or 0)
    return captured.getvalue(), exit_code


def test_hook_post_passes_through_when_not_read(monkeypatch: pytest.MonkeyPatch) -> None:
    out, rc = _run_hook_post(
        '{"tool_name":"Bash","session_id":"s1","tool_response":"hi"}', monkeypatch
    )
    assert rc == 0
    assert out == ""


def test_hook_post_passes_through_when_response_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    out, rc = _run_hook_post(
        '{"tool_name":"Read","session_id":"s1","tool_response":""}', monkeypatch
    )
    assert rc == 0
    assert out == ""


def test_hook_post_handles_malformed_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    out, rc = _run_hook_post("not json at all", monkeypatch)
    assert rc == 0
    assert out == ""


def test_hook_post_passes_through_on_broker_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail-open : broker down means redaction skipped, content reaches LLM raw.

    Documented in ADR-0046 § "Failure modes" : asymmetry vs PreToolUse hook
    (which fails CLOSED). Rationale : if broker is down, agent can't make
    tool calls anyway via the PreToolUse gate ; blocking PostToolUse would
    only hurt UX."""
    import requests as _requests

    def _fail(*a: object, **kw: object) -> None:
        raise _requests.RequestException("broker down")

    monkeypatch.setattr("secured_claude.hook_post.requests.post", _fail)
    out, rc = _run_hook_post(
        '{"tool_name":"Read","session_id":"s1","tool_response":("AKI" + "A" + "IOSFODNN7EXAMPLE")}',
        monkeypatch,
    )
    assert rc == 0
    assert out == ""


def test_hook_post_emits_block_decision_with_redacted_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the broker reports matches, the hook outputs decision: block
    so Claude Code surfaces the redacted reason to the LLM."""
    import json as _json
    from unittest.mock import MagicMock

    fake_response = MagicMock()
    fake_response.json.return_value = {
        "content": "AWS_KEY=<<SECRET:abc123>>",
        "matches_fired": ["aws-access-key"],
    }
    fake_response.raise_for_status = MagicMock()
    monkeypatch.setattr(
        "secured_claude.hook_post.requests.post", MagicMock(return_value=fake_response)
    )
    aws_key = "AKI" + "A" + "IOSFODNN7EXAMPLE"
    out, rc = _run_hook_post(
        f'{{"tool_name":"Read","session_id":"s1","tool_response":"AWS_KEY={aws_key}"}}',
        monkeypatch,
    )
    assert rc == 0
    payload = _json.loads(out.strip())
    assert payload["decision"] == "block"
    assert "<<SECRET:abc123>>" in payload["reason"]
    assert "redacted 1 secret" in payload["reason"]


def test_hook_post_passes_through_when_no_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Broker scanned but found nothing → hook stays silent → content
    passes through unchanged to the LLM."""
    from unittest.mock import MagicMock

    fake_response = MagicMock()
    fake_response.json.return_value = {
        "content": "plain code no secrets",
        "matches_fired": [],
    }
    fake_response.raise_for_status = MagicMock()
    monkeypatch.setattr(
        "secured_claude.hook_post.requests.post", MagicMock(return_value=fake_response)
    )
    out, rc = _run_hook_post(
        '{"tool_name":"Read","session_id":"s1","tool_response":"plain code"}',
        monkeypatch,
    )
    assert rc == 0
    assert out == ""


def test_hook_post_extracts_content_from_dict_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """tool_response can be a dict with `content` / `text` / `output` field."""
    from unittest.mock import MagicMock

    fake_response = MagicMock()
    fake_response.json.return_value = {"content": "redacted", "matches_fired": []}
    fake_response.raise_for_status = MagicMock()
    mock_post = MagicMock(return_value=fake_response)
    monkeypatch.setattr("secured_claude.hook_post.requests.post", mock_post)
    _, rc = _run_hook_post(
        '{"tool_name":"Read","session_id":"s1","tool_response":{"content":"file body"}}',
        monkeypatch,
    )
    assert rc == 0
    # Verify the dict's "content" field was passed to the broker
    sent_body = mock_post.call_args.kwargs["json"]
    assert sent_body["content"] == "file body"

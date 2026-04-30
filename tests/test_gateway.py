"""Tests for the FastAPI gateway (ADR-0001, ADR-0004, ADR-0027)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from secured_claude.cerbos_client import CheckResult
from secured_claude.gateway import load_principals, make_app, map_tool_to_resource
from secured_claude.store import Store


def _make_app(
    tmp_path: Path,
    *,
    allow: bool,
    principals: dict[str, dict[str, Any]] | None = None,
) -> tuple[TestClient, Store, MagicMock]:
    cerbos = MagicMock()
    cerbos.check.return_value = CheckResult(
        allow=allow,
        reason=f"effect={'EFFECT_ALLOW' if allow else 'EFFECT_DENY'}",
        duration_ms=3,
        raw={},
    )
    store = Store(path=tmp_path / "test.db")
    app = make_app(cerbos=cerbos, store=store, principals=principals)
    return TestClient(app), store, cerbos


def test_check_allow_logs_to_store(tmp_path: Path) -> None:
    client, store, _cerbos = _make_app(tmp_path, allow=True)
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
    client, store, _cerbos = _make_app(tmp_path, allow=False)
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
    client, _store, _cerbos = _make_app(tmp_path, allow=True)
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


# ────────────────────────────────────────────────────────────────────
# ADR-0027 — multi-principal directory
# ────────────────────────────────────────────────────────────────────


def test_default_principal_uses_minimal_attrs(tmp_path: Path) -> None:
    """The default principal_id maps to roles=[agent], trust_level=0."""
    # Inject a minimal directory ; default principal is [agent, claude_agent]
    # since Cerbos's parentRoles requires the derived role explicit in the
    # principal's role list (see config/principals.yaml comment + ADR-0033).
    principals = {
        "claude-code-default": {
            "roles": ["agent", "claude_agent"],
            "attributes": {"trust_level": 0},
        },
    }
    client, _store, cerbos = _make_app(tmp_path, allow=True, principals=principals)
    client.post(
        "/check",
        json={
            "tool": "Read",
            "tool_input": {"file_path": "/workspace/foo.py"},
            "principal_id": "claude-code-default",
            "session_id": "s1",
        },
    )
    call = cerbos.check.call_args
    assert call.kwargs["principal_roles"] == ["agent", "claude_agent"]
    assert call.kwargs["principal_attr"] == {"trust_level": 0}


def test_trusted_principal_passes_higher_trust_level(tmp_path: Path) -> None:
    """A principal with trust_level=1 in the directory passes through to Cerbos
    so the `trusted_agent` derived role can activate (per derived_roles.yaml)."""
    principals = {
        "claude-code-default": {"roles": ["agent"], "attributes": {"trust_level": 0}},
        "claude-code-trusted": {"roles": ["agent"], "attributes": {"trust_level": 1}},
    }
    client, _store, cerbos = _make_app(tmp_path, allow=True, principals=principals)
    client.post(
        "/check",
        json={
            "tool": "Bash",
            "tool_input": {"command": "ls"},
            "principal_id": "claude-code-trusted",
            "session_id": "s1",
        },
    )
    call = cerbos.check.call_args
    assert call.kwargs["principal_id"] == "claude-code-trusted"
    assert call.kwargs["principal_attr"]["trust_level"] == 1


def test_audit_only_principal_passes_scope(tmp_path: Path) -> None:
    """An auditor principal carries scope='audit-only' so the `auditor`
    derived role can activate."""
    principals = {
        "audit-only": {
            "roles": ["agent"],
            "attributes": {"scope": "audit-only", "trust_level": 0},
        },
    }
    client, _store, cerbos = _make_app(tmp_path, allow=True, principals=principals)
    client.post(
        "/check",
        json={
            "tool": "Read",
            "tool_input": {"file_path": "/workspace/audit.db"},
            "principal_id": "audit-only",
            "session_id": "s1",
        },
    )
    call = cerbos.check.call_args
    assert call.kwargs["principal_attr"]["scope"] == "audit-only"


def test_unknown_principal_falls_back_to_default_attrs(tmp_path: Path) -> None:
    """A principal_id not in the directory still gets a check (fail-open is
    safe : the resulting roles=[agent, claude_agent] + trust_level=0 are
    minimal, and the Cerbos policies still gate every action)."""
    principals = {
        "claude-code-default": {
            "roles": ["agent", "claude_agent"],
            "attributes": {"trust_level": 0},
        },
    }
    client, _store, cerbos = _make_app(tmp_path, allow=True, principals=principals)
    client.post(
        "/check",
        json={
            "tool": "Read",
            "tool_input": {"file_path": "/workspace/foo.py"},
            "principal_id": "some-unknown-principal",
            "session_id": "s1",
        },
    )
    call = cerbos.check.call_args
    # Roles + attrs come from the default fallback ; principal_id is preserved
    # in the audit log so the unknown principal is still traceable.
    assert call.kwargs["principal_id"] == "some-unknown-principal"
    assert call.kwargs["principal_roles"] == ["agent", "claude_agent"]
    assert call.kwargs["principal_attr"] == {"trust_level": 0}


def test_load_principals_from_yaml(tmp_path: Path) -> None:
    """Loader reads roles + attributes correctly from a YAML directory."""
    p = tmp_path / "principals.yaml"
    p.write_text(
        """
principals:
  claude-code-default:
    roles: [agent]
    attributes:
      trust_level: 0
  claude-code-trusted:
    roles: [agent]
    attributes:
      trust_level: 1
""",
        encoding="utf-8",
    )
    out = load_principals(p)
    assert out["claude-code-default"]["attributes"]["trust_level"] == 0
    assert out["claude-code-trusted"]["attributes"]["trust_level"] == 1


def test_load_principals_missing_file_returns_default(tmp_path: Path) -> None:
    """Missing principals.yaml → single-default fallback (matches v0.2 behaviour)."""
    out = load_principals(tmp_path / "nonexistent.yaml")
    assert "claude-code-default" in out
    assert out["claude-code-default"]["attributes"] == {"trust_level": 0}


def test_load_principals_malformed_yaml_returns_default(tmp_path: Path) -> None:
    """Malformed YAML → fallback (we never fail-closed on the principals file)."""
    p = tmp_path / "bad.yaml"
    p.write_text("principals:\n  - invalid:: not a dict\n  malformed: [\n", encoding="utf-8")
    out = load_principals(p)
    assert "claude-code-default" in out


def test_load_principals_missing_top_key_returns_default(tmp_path: Path) -> None:
    """YAML without `principals:` top key → fallback."""
    p = tmp_path / "no-key.yaml"
    p.write_text("other_section:\n  foo: bar\n", encoding="utf-8")
    out = load_principals(p)
    # Default principal includes claude_agent because Cerbos's parentRoles
    # semantics require the derived role explicit in principal.roles.
    expected = {
        "claude-code-default": {
            "roles": ["agent", "claude_agent"],
            "attributes": {"trust_level": 0},
        }
    }
    assert out == expected


def test_load_principals_skips_invalid_entries(tmp_path: Path) -> None:
    """Entries that aren't dicts, or where roles/attributes have wrong types,
    are dropped silently. Default is still injected at the end."""
    p = tmp_path / "mixed.yaml"
    p.write_text(
        """
principals:
  good-principal:
    roles: [agent]
    attributes:
      trust_level: 1
  bad-roles:
    roles: "not a list"
    attributes: {}
  bad-attributes:
    roles: [agent]
    attributes: "not a dict"
  not-a-dict: 42
""",
        encoding="utf-8",
    )
    out = load_principals(p)
    assert "good-principal" in out
    assert "bad-roles" not in out
    assert "bad-attributes" not in out
    assert "not-a-dict" not in out
    # Default always injected
    assert "claude-code-default" in out


def test_load_principals_env_override(tmp_path: Path, monkeypatch) -> None:
    """SECURED_CLAUDE_PRINCIPALS env points the loader at a non-default path."""
    p = tmp_path / "env.yaml"
    p.write_text(
        "principals:\n  custom-from-env:\n    roles: [agent]\n    attributes: {trust_level: 2}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURED_CLAUDE_PRINCIPALS", str(p))
    out = load_principals()  # no path arg → reads env
    assert "custom-from-env" in out
    assert out["custom-from-env"]["attributes"]["trust_level"] == 2


# ────────────────────────────────────────────────────────────────────
# ADR-0038 — JWT validation path in /check
# ────────────────────────────────────────────────────────────────────


def _make_app_with_verifier(
    tmp_path: Path,
    *,
    allow: bool,
    verifier: Any,
    principals: dict[str, dict[str, Any]] | None = None,
) -> tuple[TestClient, Store, MagicMock]:
    cerbos = MagicMock()
    cerbos.check.return_value = CheckResult(
        allow=allow,
        reason=f"effect={'EFFECT_ALLOW' if allow else 'EFFECT_DENY'}",
        duration_ms=2,
        raw={},
    )
    store = Store(path=tmp_path / "test.db")
    app = make_app(cerbos=cerbos, store=store, principals=principals, verifier=verifier)
    return TestClient(app), store, cerbos


def test_check_with_token_and_no_verifier_keeps_principal_id(tmp_path: Path) -> None:
    """No verifier configured → token field is ignored, principal_id stands."""
    client, store, cerbos = _make_app_with_verifier(tmp_path, allow=True, verifier=None)
    resp = client.post(
        "/check",
        json={
            "tool": "Read",
            "tool_input": {"file_path": "/workspace/foo.py"},
            "principal_id": "from-env-id",
            "session_id": "s1",
            "token": "ignored.token.string",
        },
    )
    assert resp.status_code == 200
    rows = store.query()
    assert rows[0].principal_id == "from-env-id"
    cerbos.check.assert_called_once()
    assert cerbos.check.call_args.kwargs["principal_id"] == "from-env-id"


def test_check_with_valid_token_derives_principal_from_sub(tmp_path: Path) -> None:
    """Verifier returns claims → broker uses claims['sub'] as principal_id."""
    verifier = MagicMock()
    verifier.verify_token.return_value = {"sub": "alice", "iss": "https://idp.example.com"}
    client, store, cerbos = _make_app_with_verifier(
        tmp_path,
        allow=True,
        verifier=verifier,
        principals={
            "alice": {"roles": ["trusted_agent", "agent"], "attributes": {"trust_level": 2}},
            "claude-code-default": {"roles": ["agent"], "attributes": {"trust_level": 0}},
        },
    )
    resp = client.post(
        "/check",
        json={
            "tool": "Read",
            "tool_input": {"file_path": "/workspace/foo.py"},
            "principal_id": "claude-code-default",  # ignored, JWT wins
            "session_id": "s1",
            "token": "valid.jwt.token",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approve"] is True
    rows = store.query()
    assert rows[0].principal_id == "alice"
    # Cerbos was called with alice's roles, not the default
    assert cerbos.check.call_args.kwargs["principal_id"] == "alice"
    assert "trusted_agent" in cerbos.check.call_args.kwargs["principal_roles"]


def test_check_with_invalid_token_denies_immediately(tmp_path: Path) -> None:
    """Verifier returns None → broker DENYs without consulting Cerbos."""
    verifier = MagicMock()
    verifier.verify_token.return_value = None
    client, store, cerbos = _make_app_with_verifier(tmp_path, allow=True, verifier=verifier)
    resp = client.post(
        "/check",
        json={
            "tool": "Read",
            "tool_input": {"file_path": "/workspace/foo.py"},
            "principal_id": "claude-code-default",
            "session_id": "s1",
            "token": "tampered.jwt.token",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approve"] is False
    assert "JWT validation failed" in body["reason"]
    cerbos.check.assert_not_called()
    rows = store.query()
    assert rows[0].decision == "DENY"
    assert rows[0].principal_id == "claude-code-default"


def test_check_with_token_missing_sub_denies(tmp_path: Path) -> None:
    """Valid signature but missing `sub` claim → DENY."""
    verifier = MagicMock()
    verifier.verify_token.return_value = {"iss": "https://idp.example.com"}
    client, _store, cerbos = _make_app_with_verifier(tmp_path, allow=True, verifier=verifier)
    resp = client.post(
        "/check",
        json={
            "tool": "Read",
            "tool_input": {"file_path": "/workspace/foo.py"},
            "session_id": "s1",
            "token": "token.without.sub",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approve"] is False
    assert "missing `sub`" in body["reason"]
    cerbos.check.assert_not_called()


def test_check_without_token_when_verifier_set_uses_principal_id(tmp_path: Path) -> None:
    """No token but verifier configured → principal_id field is used (back-compat)."""
    verifier = MagicMock()
    verifier.verify_token.return_value = None  # would reject IF called
    client, _store, cerbos = _make_app_with_verifier(tmp_path, allow=True, verifier=verifier)
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
    assert resp.json()["approve"] is True
    verifier.verify_token.assert_not_called()
    cerbos.check.assert_called_once()

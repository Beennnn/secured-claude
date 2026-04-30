"""Tests for the Prometheus metrics module + /metrics endpoint (ADR-0042)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import responses
from fastapi.testclient import TestClient

from secured_claude import metrics
from secured_claude.cerbos_client import CheckResult
from secured_claude.gateway import make_app
from secured_claude.principals import HTTPPrincipalProvider
from secured_claude.store import Store


def _read_counter(counter: Any, **labels: str) -> float:
    """Read a Prometheus counter's current value (with optional labels)."""
    if labels:
        return counter.labels(**labels)._value.get()  # type: ignore[no-any-return]
    return counter._value.get()  # type: ignore[no-any-return]


# ────────────────────────────────────────────────────────────────────
# /metrics endpoint
# ────────────────────────────────────────────────────────────────────


def test_metrics_endpoint_serves_prometheus_text(tmp_path: Path) -> None:
    cerbos = MagicMock()
    cerbos.check.return_value = CheckResult(allow=True, reason="ok", duration_ms=2, raw={})
    app = make_app(cerbos=cerbos, store=Store(path=tmp_path / "test.db"))
    client = TestClient(app)
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    body = resp.text
    # All counter families should appear in the exposition output, even if 0.
    assert "secured_claude_principals_fetch_total" in body
    assert "secured_claude_jwt_verify_total" in body
    assert "secured_claude_jwks_fetch_total" in body
    assert "secured_claude_check_decisions_total" in body
    assert "secured_claude_multi_issuer_routing_total" in body


def test_check_decision_counter_increments_on_allow(tmp_path: Path) -> None:
    before = _read_counter(metrics.CHECK_DECISIONS_TOTAL, decision="ALLOW")
    cerbos = MagicMock()
    cerbos.check.return_value = CheckResult(allow=True, reason="ok", duration_ms=2, raw={})
    app = make_app(cerbos=cerbos, store=Store(path=tmp_path / "test.db"))
    client = TestClient(app)
    client.post(
        "/check",
        json={"tool": "Read", "tool_input": {"file_path": "/workspace/foo.py"}},
    )
    after = _read_counter(metrics.CHECK_DECISIONS_TOTAL, decision="ALLOW")
    assert after == before + 1


def test_check_decision_counter_increments_on_deny(tmp_path: Path) -> None:
    before = _read_counter(metrics.CHECK_DECISIONS_TOTAL, decision="DENY")
    cerbos = MagicMock()
    cerbos.check.return_value = CheckResult(
        allow=False, reason="effect=EFFECT_DENY", duration_ms=2, raw={}
    )
    app = make_app(cerbos=cerbos, store=Store(path=tmp_path / "test.db"))
    client = TestClient(app)
    client.post("/check", json={"tool": "Read", "tool_input": {"file_path": "/etc/passwd"}})
    after = _read_counter(metrics.CHECK_DECISIONS_TOTAL, decision="DENY")
    assert after == before + 1


def test_check_decision_counter_increments_on_cerbos_failure(tmp_path: Path) -> None:
    before = _read_counter(metrics.CHECK_DECISIONS_TOTAL, decision="cerbos_unavailable")
    cerbos = MagicMock()
    cerbos.check.side_effect = ConnectionError("simulated cerbos down")
    app = make_app(cerbos=cerbos, store=Store(path=tmp_path / "test.db"))
    client = TestClient(app)
    resp = client.post(
        "/check", json={"tool": "Read", "tool_input": {"file_path": "/workspace/foo.py"}}
    )
    assert resp.json()["approve"] is False
    after = _read_counter(metrics.CHECK_DECISIONS_TOTAL, decision="cerbos_unavailable")
    assert after == before + 1


def test_check_decision_counter_increments_on_jwt_deny(tmp_path: Path) -> None:
    before = _read_counter(metrics.CHECK_DECISIONS_TOTAL, decision="jwt_deny")
    cerbos = MagicMock()
    cerbos.check.return_value = CheckResult(allow=True, reason="ok", duration_ms=2, raw={})
    verifier = MagicMock()
    verifier.verify_token.return_value = None  # simulate signature fail
    app = make_app(cerbos=cerbos, store=Store(path=tmp_path / "test.db"), verifier=verifier)
    client = TestClient(app)
    client.post(
        "/check",
        json={
            "tool": "Read",
            "tool_input": {"file_path": "/workspace/foo.py"},
            "token": "tampered",
        },
    )
    after = _read_counter(metrics.CHECK_DECISIONS_TOTAL, decision="jwt_deny")
    assert after == before + 1


# ────────────────────────────────────────────────────────────────────
# Provider-side counters
# ────────────────────────────────────────────────────────────────────


@responses.activate
def test_principals_fetch_counter_increments_on_success() -> None:
    before = _read_counter(metrics.PRINCIPALS_FETCH_TOTAL, outcome="success")
    responses.add(
        responses.GET,
        "http://idp.example.com/principals",
        json={"principals": {}},
        status=200,
    )
    HTTPPrincipalProvider("http://idp.example.com/principals").load()
    after = _read_counter(metrics.PRINCIPALS_FETCH_TOTAL, outcome="success")
    assert after == before + 1


@responses.activate
def test_principals_fetch_counter_increments_on_error() -> None:
    before = _read_counter(metrics.PRINCIPALS_FETCH_TOTAL, outcome="error")
    responses.add(responses.GET, "http://idp.example.com/principals", status=503)
    HTTPPrincipalProvider("http://idp.example.com/principals").load()
    after = _read_counter(metrics.PRINCIPALS_FETCH_TOTAL, outcome="error")
    assert after == before + 1


@responses.activate
def test_principals_cache_hit_counter_increments(monkeypatch: Any) -> None:
    """Empty {principals: {}} would equal the fallback so cache wouldn't be set ;
    use a real principal so the parsed dict differs from `_fallback()`."""
    before = _read_counter(metrics.PRINCIPALS_CACHE_HIT_TOTAL)
    responses.add(
        responses.GET,
        "http://idp.example.com/principals",
        json={"principals": {"alice": {"roles": ["agent"], "attributes": {"trust_level": 1}}}},
        status=200,
    )
    p = HTTPPrincipalProvider("http://idp.example.com/principals", cache_ttl_s=10.0)
    fake_time = [0.0]
    monkeypatch.setattr(p, "_now", lambda: fake_time[0])
    p.load()  # cache miss + populate (parsed != fallback so cache IS set)
    fake_time[0] = 5.0
    p.load()  # cache hit
    after = _read_counter(metrics.PRINCIPALS_CACHE_HIT_TOTAL)
    assert after == before + 1


def test_metrics_render_returns_bytes() -> None:
    out = metrics.render()
    assert isinstance(out, bytes)
    assert b"secured_claude_" in out


def test_metrics_content_type_is_prometheus_format() -> None:
    ct = metrics.content_type()
    assert "text/plain" in ct
    assert "version=" in ct

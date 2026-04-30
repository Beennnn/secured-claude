"""Tests for the PrincipalProvider abstraction (ADR-0034)."""

from __future__ import annotations

from pathlib import Path

import pytest
import responses

from secured_claude.principals import (
    DEFAULT_PRINCIPAL,
    DEFAULT_PRINCIPAL_ID,
    HTTPPrincipalProvider,
    YAMLPrincipalProvider,
    make_provider,
)

# ────────────────────────────────────────────────────────────────────
# YAMLPrincipalProvider — same behaviour as v0.3.1's load_principals
# ────────────────────────────────────────────────────────────────────


def test_yaml_provider_reads_valid_file(tmp_path: Path) -> None:
    p = tmp_path / "ok.yaml"
    p.write_text(
        """
principals:
  alice:
    roles: [agent, claude_agent]
    attributes:
      trust_level: 1
""",
        encoding="utf-8",
    )
    out = YAMLPrincipalProvider(p).load()
    assert "alice" in out
    assert out["alice"]["roles"] == ["agent", "claude_agent"]
    assert out["alice"]["attributes"]["trust_level"] == 1
    # Default always injected for safety
    assert DEFAULT_PRINCIPAL_ID in out


def test_yaml_provider_missing_file_returns_fallback(tmp_path: Path) -> None:
    out = YAMLPrincipalProvider(tmp_path / "missing.yaml").load()
    assert out == {DEFAULT_PRINCIPAL_ID: DEFAULT_PRINCIPAL}


def test_yaml_provider_malformed_returns_fallback(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("principals:\n  - invalid:: not\n  malformed: [\n", encoding="utf-8")
    out = YAMLPrincipalProvider(p).load()
    assert out == {DEFAULT_PRINCIPAL_ID: DEFAULT_PRINCIPAL}


def test_yaml_provider_skips_invalid_entries(tmp_path: Path) -> None:
    p = tmp_path / "mixed.yaml"
    p.write_text(
        """
principals:
  good:
    roles: [agent, claude_agent]
    attributes: {trust_level: 1}
  bad-roles:
    roles: "not a list"
    attributes: {}
  not-a-mapping: 42
""",
        encoding="utf-8",
    )
    out = YAMLPrincipalProvider(p).load()
    assert "good" in out
    assert "bad-roles" not in out
    assert "not-a-mapping" not in out
    assert DEFAULT_PRINCIPAL_ID in out


# ────────────────────────────────────────────────────────────────────
# HTTPPrincipalProvider — fetches from a URL (mocked via responses)
# ────────────────────────────────────────────────────────────────────


@responses.activate
def test_http_provider_fetches_json() -> None:
    body = {
        "principals": {
            "alice": {"roles": ["agent", "claude_agent"], "attributes": {"trust_level": 2}},
            "bob": {"roles": ["agent", "claude_agent"], "attributes": {"trust_level": 0}},
        }
    }
    responses.add(responses.GET, "http://idp.example.com/principals", json=body, status=200)
    out = HTTPPrincipalProvider("http://idp.example.com/principals").load()
    assert "alice" in out
    assert out["alice"]["attributes"]["trust_level"] == 2
    assert "bob" in out
    assert DEFAULT_PRINCIPAL_ID in out


@responses.activate
def test_http_provider_fetches_yaml() -> None:
    body = """
principals:
  alice:
    roles: [agent, claude_agent]
    attributes:
      trust_level: 2
"""
    responses.add(
        responses.GET,
        "http://idp.example.com/principals.yaml",
        body=body,
        status=200,
        content_type="application/x-yaml",
    )
    out = HTTPPrincipalProvider("http://idp.example.com/principals.yaml").load()
    assert "alice" in out
    assert out["alice"]["attributes"]["trust_level"] == 2


@responses.activate
def test_http_provider_returns_fallback_on_5xx() -> None:
    responses.add(responses.GET, "http://idp.example.com/principals", status=503)
    out = HTTPPrincipalProvider("http://idp.example.com/principals").load()
    assert out == {DEFAULT_PRINCIPAL_ID: DEFAULT_PRINCIPAL}


@responses.activate
def test_http_provider_returns_fallback_on_unreachable() -> None:
    # No `responses.add` for this URL → connection error → fallback.
    out = HTTPPrincipalProvider("http://idp.unreachable.example/principals").load()
    assert out == {DEFAULT_PRINCIPAL_ID: DEFAULT_PRINCIPAL}


@responses.activate
def test_http_provider_returns_fallback_on_invalid_json() -> None:
    responses.add(
        responses.GET,
        "http://idp.example.com/principals",
        body="<html>not json</html>",
        status=200,
    )
    out = HTTPPrincipalProvider("http://idp.example.com/principals").load()
    assert out == {DEFAULT_PRINCIPAL_ID: DEFAULT_PRINCIPAL}


# ────────────────────────────────────────────────────────────────────
# make_provider — env-driven selection
# ────────────────────────────────────────────────────────────────────


def test_make_provider_yaml_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECURED_CLAUDE_IDP_URL", raising=False)
    monkeypatch.delenv("SECURED_CLAUDE_PRINCIPALS", raising=False)
    p = make_provider()
    assert isinstance(p, YAMLPrincipalProvider)
    assert p.path == Path("config/principals.yaml")


def test_make_provider_yaml_with_env_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    custom = tmp_path / "custom.yaml"
    custom.write_text("principals: {}\n", encoding="utf-8")
    monkeypatch.delenv("SECURED_CLAUDE_IDP_URL", raising=False)
    monkeypatch.setenv("SECURED_CLAUDE_PRINCIPALS", str(custom))
    p = make_provider()
    assert isinstance(p, YAMLPrincipalProvider)
    assert p.path == custom


def test_make_provider_http_when_idp_url_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "http://idp.example.com/principals")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.url == "http://idp.example.com/principals"
    assert p.timeout_s == 5.0  # default


def test_make_provider_http_with_custom_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "http://idp.example.com/principals")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_TIMEOUT_S", "12")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.timeout_s == 12.0


def test_make_provider_http_invalid_timeout_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "http://idp.example.com/principals")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_TIMEOUT_S", "not-a-number")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.timeout_s == 5.0


def test_make_provider_empty_idp_url_falls_through_to_yaml(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty SECURED_CLAUDE_IDP_URL is treated as unset (avoids surprises if
    the operator left the env defined but blank in their compose)."""
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "")
    p = make_provider()
    assert isinstance(p, YAMLPrincipalProvider)


# ────────────────────────────────────────────────────────────────────
# ADR-0037 — TTL cache + bearer auth on HTTPPrincipalProvider
# ────────────────────────────────────────────────────────────────────


@responses.activate
def test_http_provider_caches_within_ttl() -> None:
    """Two load() calls within TTL → only one network call ; second returns
    the cached dict by reference."""
    body = {
        "principals": {
            "alice": {"roles": ["agent", "claude_agent"], "attributes": {"trust_level": 1}},
        }
    }
    responses.add(responses.GET, "http://idp.example.com/principals", json=body, status=200)
    p = HTTPPrincipalProvider("http://idp.example.com/principals", cache_ttl_s=300.0)
    out1 = p.load()
    out2 = p.load()
    assert out1 == out2
    assert "alice" in out1
    # Only ONE HTTP call recorded (cache hit on the second load).
    assert len(responses.calls) == 1


@responses.activate
def test_http_provider_refetches_after_ttl_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When cache_ttl_s elapses, the next load() re-fetches."""
    body_v1 = {"principals": {"alice": {"roles": ["agent"], "attributes": {"trust_level": 0}}}}
    body_v2 = {"principals": {"alice": {"roles": ["agent"], "attributes": {"trust_level": 5}}}}
    responses.add(responses.GET, "http://idp.example.com/principals", json=body_v1, status=200)
    responses.add(responses.GET, "http://idp.example.com/principals", json=body_v2, status=200)
    p = HTTPPrincipalProvider("http://idp.example.com/principals", cache_ttl_s=10.0)
    # Manual time control via monkeypatching _now.
    fake_time = [0.0]
    monkeypatch.setattr(p, "_now", lambda: fake_time[0])
    out1 = p.load()
    assert out1["alice"]["attributes"]["trust_level"] == 0
    # Advance past the TTL.
    fake_time[0] = 11.0
    out2 = p.load()
    assert out2["alice"]["attributes"]["trust_level"] == 5
    assert len(responses.calls) == 2


@responses.activate
def test_http_provider_serves_stale_on_5xx(monkeypatch: pytest.MonkeyPatch) -> None:
    """If a fresh fetch fails AND we have a cached response, the provider
    serves the stale cache instead of falling back to default. Trades
    freshness for availability when the IdP is briefly down."""
    body_ok = {
        "principals": {
            "alice": {"roles": ["agent", "claude_agent"], "attributes": {"trust_level": 2}},
        }
    }
    responses.add(responses.GET, "http://idp.example.com/principals", json=body_ok, status=200)
    responses.add(responses.GET, "http://idp.example.com/principals", status=503)
    p = HTTPPrincipalProvider("http://idp.example.com/principals", cache_ttl_s=10.0)
    fake_time = [0.0]
    monkeypatch.setattr(p, "_now", lambda: fake_time[0])
    # First load : success, cached.
    p.load()
    # TTL expires + IdP returns 5xx.
    fake_time[0] = 11.0
    out = p.load()
    # We get the STALE cache, not the single-default fallback.
    assert "alice" in out
    assert out["alice"]["attributes"]["trust_level"] == 2


@responses.activate
def test_http_provider_falls_back_when_no_cache_and_5xx() -> None:
    """First-load 5xx with no prior cache → single-default fallback."""
    responses.add(responses.GET, "http://idp.example.com/principals", status=503)
    p = HTTPPrincipalProvider("http://idp.example.com/principals")
    out = p.load()
    assert out == {DEFAULT_PRINCIPAL_ID: DEFAULT_PRINCIPAL}


@responses.activate
def test_http_provider_sends_bearer_token() -> None:
    """When `bearer_token` is set, the Authorization header is on the request."""
    body = {"principals": {}}
    responses.add(responses.GET, "http://idp.example.com/principals", json=body, status=200)
    p = HTTPPrincipalProvider("http://idp.example.com/principals", bearer_token="s3cret-token-xyz")
    p.load()
    assert len(responses.calls) == 1
    auth = responses.calls[0].request.headers.get("Authorization")
    assert auth == "Bearer s3cret-token-xyz"


@responses.activate
def test_http_provider_no_bearer_when_token_unset() -> None:
    """Default no Authorization header ; doesn't accidentally leak something."""
    body = {"principals": {}}
    responses.add(responses.GET, "http://idp.example.com/principals", json=body, status=200)
    p = HTTPPrincipalProvider("http://idp.example.com/principals")
    p.load()
    auth = responses.calls[0].request.headers.get("Authorization")
    assert auth is None


def test_make_provider_picks_up_cache_ttl_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "http://idp.example.com/principals")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_CACHE_TTL_S", "60")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.cache_ttl_s == 60.0


def test_make_provider_picks_up_bearer_token_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "http://idp.example.com/principals")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_BEARER_TOKEN", "abc-secret")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.bearer_token == "abc-secret"


def test_make_provider_invalid_cache_ttl_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "http://idp.example.com/principals")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_CACHE_TTL_S", "not-a-number")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.cache_ttl_s == 300.0  # default


# ────────────────────────────────────────────────────────────────────
# ADR-0039 — max_stale_age_s on HTTPPrincipalProvider
# ────────────────────────────────────────────────────────────────────


@responses.activate
def test_http_provider_drops_stale_cache_after_max_stale_age(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When stale cache outlives max_stale_age_s, fall back to single-default."""
    body_ok = {"principals": {"alice": {"roles": ["agent"], "attributes": {"trust_level": 2}}}}
    responses.add(responses.GET, "http://idp.example.com/principals", json=body_ok, status=200)
    responses.add(responses.GET, "http://idp.example.com/principals", status=503)
    responses.add(responses.GET, "http://idp.example.com/principals", status=503)
    p = HTTPPrincipalProvider(
        "http://idp.example.com/principals",
        cache_ttl_s=10.0,
        max_stale_age_s=20.0,
    )
    fake_time = [0.0]
    monkeypatch.setattr(p, "_now", lambda: fake_time[0])
    # t=0 : success, cached at ts=0
    p.load()
    # t=15 : TTL expired (10) but cache age 15 < max_stale_age (20) → stale serve
    fake_time[0] = 15.0
    out = p.load()
    assert "alice" in out, "still within max_stale_age, should serve stale"
    # t=35 : cache age 35 > max_stale_age (20) → drop + single-default fallback
    fake_time[0] = 35.0
    out = p.load()
    assert out == {DEFAULT_PRINCIPAL_ID: DEFAULT_PRINCIPAL}
    assert p._cache is None, "cache should be dropped after max-stale exceeded"


@responses.activate
def test_http_provider_max_stale_age_none_serves_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """max_stale_age_s=None preserves v0.6.1 behaviour (stale forever)."""
    body_ok = {"principals": {"alice": {"roles": ["agent"], "attributes": {"trust_level": 2}}}}
    responses.add(responses.GET, "http://idp.example.com/principals", json=body_ok, status=200)
    responses.add(responses.GET, "http://idp.example.com/principals", status=503)
    p = HTTPPrincipalProvider(
        "http://idp.example.com/principals",
        cache_ttl_s=10.0,
        max_stale_age_s=None,
    )
    fake_time = [0.0]
    monkeypatch.setattr(p, "_now", lambda: fake_time[0])
    p.load()
    fake_time[0] = 1_000_000.0  # extreme age
    out = p.load()
    assert "alice" in out, "max_stale_age=None means stale-forever (v0.6.1 default)"


def test_make_provider_picks_up_max_stale_age_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "http://idp.example.com/principals")
    monkeypatch.setenv("SECURED_CLAUDE_MAX_STALE_AGE_S", "300")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.max_stale_age_s == 300.0


def test_make_provider_max_stale_age_unset_means_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECURED_CLAUDE_MAX_STALE_AGE_S", raising=False)
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "http://idp.example.com/principals")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.max_stale_age_s is None


def test_make_provider_max_stale_age_invalid_falls_back_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "http://idp.example.com/principals")
    monkeypatch.setenv("SECURED_CLAUDE_MAX_STALE_AGE_S", "not-a-number")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.max_stale_age_s is None


# ────────────────────────────────────────────────────────────────────
# ADR-0040 — mTLS client cert/key pair
# ────────────────────────────────────────────────────────────────────


def test_http_provider_cert_kwarg_set_when_both_paths_provided() -> None:
    p = HTTPPrincipalProvider(
        "http://idp.example.com/principals",
        client_cert_path="/etc/ssl/client.crt",
        client_key_path="/etc/ssl/client.key",
    )
    assert p._cert_kwarg() == ("/etc/ssl/client.crt", "/etc/ssl/client.key")


def test_http_provider_cert_kwarg_none_when_either_path_missing() -> None:
    p_cert_only = HTTPPrincipalProvider(
        "http://idp.example.com/principals",
        client_cert_path="/etc/ssl/client.crt",
        client_key_path=None,
    )
    assert p_cert_only._cert_kwarg() is None
    p_key_only = HTTPPrincipalProvider(
        "http://idp.example.com/principals",
        client_cert_path=None,
        client_key_path="/etc/ssl/client.key",
    )
    assert p_key_only._cert_kwarg() is None
    p_neither = HTTPPrincipalProvider("http://idp.example.com/principals")
    assert p_neither._cert_kwarg() is None


def test_http_provider_passes_cert_kwarg_to_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the `cert=` kwarg is forwarded to requests.get on every fetch."""
    from unittest.mock import MagicMock

    mock_get = MagicMock()
    mock_get.return_value.text = '{"principals": {}}'
    mock_get.return_value.raise_for_status = MagicMock()
    monkeypatch.setattr("secured_claude.principals.requests.get", mock_get)
    p = HTTPPrincipalProvider(
        "http://idp.example.com/principals",
        client_cert_path="/etc/ssl/client.crt",
        client_key_path="/etc/ssl/client.key",
    )
    p.load()
    assert mock_get.call_count == 1
    kwargs = mock_get.call_args.kwargs
    assert kwargs.get("cert") == ("/etc/ssl/client.crt", "/etc/ssl/client.key")


def test_http_provider_no_cert_kwarg_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default config → cert kwarg is None (mutual TLS not requested)."""
    from unittest.mock import MagicMock

    mock_get = MagicMock()
    mock_get.return_value.text = '{"principals": {}}'
    mock_get.return_value.raise_for_status = MagicMock()
    monkeypatch.setattr("secured_claude.principals.requests.get", mock_get)
    p = HTTPPrincipalProvider("http://idp.example.com/principals")
    p.load()
    kwargs = mock_get.call_args.kwargs
    assert kwargs.get("cert") is None


def test_make_provider_picks_up_mtls_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "https://idp.example.com/principals")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_CLIENT_CERT_PATH", "/etc/ssl/client.crt")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_CLIENT_KEY_PATH", "/etc/ssl/client.key")
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p.client_cert_path == "/etc/ssl/client.crt"
    assert p.client_key_path == "/etc/ssl/client.key"


def test_make_provider_mtls_partial_env_treated_as_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cert path only → mTLS not activated (both halves required)."""
    monkeypatch.setenv("SECURED_CLAUDE_IDP_URL", "https://idp.example.com/principals")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_CLIENT_CERT_PATH", "/etc/ssl/client.crt")
    monkeypatch.delenv("SECURED_CLAUDE_IDP_CLIENT_KEY_PATH", raising=False)
    p = make_provider()
    assert isinstance(p, HTTPPrincipalProvider)
    assert p._cert_kwarg() is None

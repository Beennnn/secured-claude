"""Tests for the OIDC verifier (ADR-0038).

Strategy : generate an RSA key pair, expose the public key via a mocked
JWKS endpoint + a mocked /.well-known/openid-configuration, then sign
JWTs with the private key. Pass them through OIDCVerifier and assert
claims dict (happy path) or None (reject path).
"""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
import responses
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from secured_claude.oidc import OIDCVerifier, make_verifier

ISSUER = "https://idp.example.com"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/jwks.json"
KID = "test-kid-1"


@pytest.fixture
def rsa_key_pair() -> tuple[Any, Any]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    return private, public


@pytest.fixture
def jwks_payload(rsa_key_pair: tuple[Any, Any]) -> dict[str, Any]:
    """Build a minimal JWKS document containing the test public key."""
    _private, public = rsa_key_pair
    nums = public.public_numbers()
    import base64

    def _b64u(n: int) -> str:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": _b64u(nums.n),
                "e": _b64u(nums.e),
            }
        ]
    }


def _sign(private_key: Any, claims: dict[str, Any]) -> str:
    """Sign a JWT with the test private key + the matching kid."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": KID})


# ────────────────────────────────────────────────────────────────────
# OIDCVerifier — happy + reject paths
# ────────────────────────────────────────────────────────────────────


@responses.activate
def test_verifier_accepts_valid_token(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)

    token = _sign(
        private,
        {
            "iss": ISSUER,
            "sub": "alice",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
        },
    )
    v = OIDCVerifier(issuer=ISSUER)
    claims = v.verify_token(token)
    assert claims is not None
    assert claims["sub"] == "alice"
    assert claims["iss"] == ISSUER


@responses.activate
def test_verifier_rejects_expired_token(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)

    token = _sign(
        private,
        {
            "iss": ISSUER,
            "sub": "alice",
            "exp": int(time.time()) - 60,  # already past
            "iat": int(time.time()) - 120,
        },
    )
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is None


@responses.activate
def test_verifier_rejects_wrong_issuer(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)

    token = _sign(
        private,
        {
            "iss": "https://attacker.example.com",
            "sub": "alice",
            "exp": int(time.time()) + 60,
        },
    )
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is None


@responses.activate
def test_verifier_enforces_audience_when_configured(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)

    token = _sign(
        private,
        {
            "iss": ISSUER,
            "sub": "alice",
            "aud": "secured-claude",
            "exp": int(time.time()) + 60,
        },
    )
    # No aud → token's aud is fine but verifier doesn't enforce
    v_no_aud = OIDCVerifier(issuer=ISSUER)
    assert v_no_aud.verify_token(token) is not None
    # Configured aud → must match
    v_match = OIDCVerifier(issuer=ISSUER, audience="secured-claude")
    assert v_match.verify_token(token) is not None
    # Configured aud != token aud → reject
    v_mismatch = OIDCVerifier(issuer=ISSUER, audience="other-app")
    assert v_mismatch.verify_token(token) is None


@responses.activate
def test_verifier_rejects_unsigned_token(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)

    # Token with alg=none — classic CVE-2015-9235 attempt. PyJWT rejects
    # by default ; we still verify the verifier flow rejects it.
    token = jwt.encode({"iss": ISSUER, "sub": "alice"}, "", algorithm="none")
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is None


@responses.activate
def test_verifier_rejects_signed_with_other_key(jwks_payload: dict[str, Any]) -> None:
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)

    # Sign with a different RSA key — no kid match in JWKS → reject
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = other.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode(
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
        pem,
        algorithm="RS256",
        headers={"kid": "unknown-kid"},
    )
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is None


@responses.activate
def test_verifier_handles_discovery_5xx_no_cache(jwks_payload: dict[str, Any]) -> None:
    responses.add(responses.GET, DISCOVERY_URL, json={"err": "down"}, status=500)
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token("any.token.string") is None


@responses.activate
def test_verifier_handles_jwks_5xx_no_cache(jwks_payload: dict[str, Any]) -> None:
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json={"err": "down"}, status=500)
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token("any.token.string") is None


def test_verifier_returns_none_for_empty_token() -> None:
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token("") is None


@responses.activate
def test_verifier_sends_bearer_on_discovery_and_jwks(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)

    token = _sign(
        private,
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
    )
    v = OIDCVerifier(issuer=ISSUER, bearer_token="abc-secret")
    claims = v.verify_token(token)
    assert claims is not None
    # Both calls (discovery + jwks) must carry the Authorization header
    assert len(responses.calls) >= 2
    for call in responses.calls:
        assert call.request.headers.get("Authorization") == "Bearer abc-secret"


# ────────────────────────────────────────────────────────────────────
# make_verifier() factory — env-driven configuration
# ────────────────────────────────────────────────────────────────────


def test_make_verifier_returns_none_when_issuer_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECURED_CLAUDE_IDP_ISSUER", raising=False)
    assert make_verifier() is None


def test_make_verifier_returns_none_when_issuer_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "   ")
    assert make_verifier() is None


def test_make_verifier_picks_up_issuer_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com")
    v = make_verifier()
    assert v is not None
    assert v.issuer == "https://idp.example.com"
    assert v.audience is None
    assert v.jwks_cache_ttl_s == 3600.0


def test_make_verifier_picks_up_audience_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SECURED_CLAUDE_OIDC_AUDIENCE", "secured-claude")
    v = make_verifier()
    assert v is not None
    assert v.audience == "secured-claude"


def test_make_verifier_picks_up_jwks_ttl_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SECURED_CLAUDE_OIDC_JWKS_TTL_S", "60")
    v = make_verifier()
    assert v is not None
    assert v.jwks_cache_ttl_s == 60.0


def test_make_verifier_invalid_jwks_ttl_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SECURED_CLAUDE_OIDC_JWKS_TTL_S", "not-a-float")
    v = make_verifier()
    assert v is not None
    assert v.jwks_cache_ttl_s == 3600.0


def test_make_verifier_picks_up_bearer_token_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_BEARER_TOKEN", "abc-secret")
    v = make_verifier()
    assert v is not None
    assert v.bearer_token == "abc-secret"


def test_make_verifier_strips_trailing_slash_in_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com/")
    v = make_verifier()
    assert v is not None
    assert v.issuer == "https://idp.example.com"


# A serialised payload that PyJWT will raise on the first decode call ;
# avoids the "no jwks" branch above and probes the validation-failure path.
def test_verifier_returns_none_for_garbage_token(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    @responses.activate
    def _run() -> None:
        responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
        responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)
        v = OIDCVerifier(issuer=ISSUER)
        assert v.verify_token("not.a.jwt") is None

    _run()


@responses.activate
def test_verifier_caches_jwks_within_ttl(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    """Two consecutive verifications should hit discovery + JWKS once each."""
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)

    token = _sign(
        private,
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
    )
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is not None
    discovery_calls = sum(1 for c in responses.calls if c.request.url.startswith(DISCOVERY_URL))
    assert discovery_calls == 1
    # Second call : discovery + jwks_uri lookup should NOT re-fetch from us.
    # PyJWKClient has its own cache so the JWKS_URL count may stay at 1.
    assert v.verify_token(token) is not None
    discovery_calls_after = sum(
        1 for c in responses.calls if c.request.url.startswith(DISCOVERY_URL)
    )
    assert discovery_calls_after == 1, "discovery should hit cache on the 2nd verification"


@responses.activate
def test_verifier_discovery_without_jwks_uri_returns_none(rsa_key_pair: tuple[Any, Any]) -> None:
    responses.add(responses.GET, DISCOVERY_URL, json={"issuer": ISSUER}, status=200)
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token("anything") is None

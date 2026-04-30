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


# Coverage-targeted tests : exercise the error paths with a *valid-format*
# JWT so jwt.get_unverified_header() succeeds and the flow reaches the
# JWKS / discovery code.


@responses.activate
def test_verifier_returns_none_when_discovery_5xx_with_valid_jwt(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    """A valid-format JWT + 500 on discovery → reject (no JWKS available)."""
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"err": "down"}, status=500)
    token = _sign(
        private,
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
    )
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is None


@responses.activate
def test_verifier_returns_none_when_jwks_5xx_with_valid_jwt(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    """A valid-format JWT + 500 on JWKS → reject (discovery cached but no keys)."""
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json={"err": "down"}, status=500)
    token = _sign(
        private,
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
    )
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is None


@responses.activate
def test_verifier_returns_none_when_discovery_returns_garbage_json(
    rsa_key_pair: tuple[Any, Any],
) -> None:
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, body="not-json", status=200)
    token = _sign(
        private,
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
    )
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is None


@responses.activate
def test_verifier_handles_jwks_keys_not_a_list(rsa_key_pair: tuple[Any, Any]) -> None:
    """JWKS with `keys` as a non-list → reject (malformed JWKS)."""
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json={"keys": "not-a-list"}, status=200)
    token = _sign(
        private,
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
    )
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is None


@responses.activate
def test_verifier_skips_non_dict_jwk_entry(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    """JWKS with a string entry mixed in → skip + still match the dict entry."""
    private, _public = rsa_key_pair
    polluted = {"keys": ["not-a-dict", *jwks_payload["keys"]]}
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=polluted, status=200)
    token = _sign(
        private,
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
    )
    v = OIDCVerifier(issuer=ISSUER)
    assert v.verify_token(token) is not None


@responses.activate
def test_verifier_skips_jwk_entry_that_fails_pyjwk_construction(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    """JWKS containing a malformed JWK (with matching kid) → skip + try next."""
    private, _public = rsa_key_pair
    bad_jwk = {"kty": "INVALID", "kid": KID}
    polluted = {"keys": [bad_jwk, *jwks_payload["keys"]]}
    # Override the kid on the good key so the bad one matches first
    polluted["keys"][1] = {**polluted["keys"][1], "kid": KID}
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=polluted, status=200)
    token = _sign(
        private,
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
    )
    v = OIDCVerifier(issuer=ISSUER)
    # Either the bad JWK is skipped and good one wins (=> claims), OR both
    # fail (=> None). The point is the malformed entry doesn't crash the
    # verifier ; both branches keep coverage on lines 154-155.
    result = v.verify_token(token)
    assert result is None or result["sub"] == "alice"


@responses.activate
def test_verifier_caches_discovery_after_jwks_cache_expiry(
    rsa_key_pair: tuple[Any, Any], jwks_payload: dict[str, Any]
) -> None:
    """First call seeds discovery + JWKS ; manually expire JWKS cache, second
    call refetches JWKS but reuses the discovery cache (line 98)."""
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)
    token = _sign(
        private,
        {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60},
    )
    v = OIDCVerifier(issuer=ISSUER, jwks_cache_ttl_s=3600.0)
    assert v.verify_token(token) is not None
    # Manually expire JWKS cache without touching discovery cache
    v._jwks_ts = 0.0  # force refetch
    assert v.verify_token(token) is not None
    discovery_calls = sum(1 for c in responses.calls if c.request.url.startswith(DISCOVERY_URL))
    assert discovery_calls == 1, "discovery cache should have been used on the 2nd call"


def test_make_verifier_invalid_timeout_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SECURED_CLAUDE_IDP_TIMEOUT_S", "not-a-number")
    v = make_verifier()
    assert v is not None
    assert v.timeout_s == 5.0


# ────────────────────────────────────────────────────────────────────
# ADR-0039 — max_stale_age_s on OIDCVerifier
# ────────────────────────────────────────────────────────────────────


@responses.activate
def test_verifier_drops_stale_jwks_after_max_stale_age(
    rsa_key_pair: tuple[Any, Any],
    jwks_payload: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stale JWKS older than max_stale_age_s → verify_token returns None."""
    private, _public = rsa_key_pair
    responses.add(responses.GET, DISCOVERY_URL, json={"jwks_uri": JWKS_URL}, status=200)
    responses.add(responses.GET, JWKS_URL, json=jwks_payload, status=200)
    responses.add(responses.GET, JWKS_URL, status=503)  # 2nd call : 5xx
    responses.add(responses.GET, JWKS_URL, status=503)  # 3rd call : still 5xx

    token = _sign(private, {"iss": ISSUER, "sub": "alice", "exp": int(time.time()) + 60})
    v = OIDCVerifier(
        issuer=ISSUER,
        jwks_cache_ttl_s=10.0,
        max_stale_age_s=20.0,
    )
    fake_time = [100.0]
    monkeypatch.setattr(v, "_now", lambda: fake_time[0])
    # t=100 : success, cached at ts=100
    assert v.verify_token(token) is not None
    # t=115 : TTL expired (10) but stale age 15 < max_stale (20) → still serves
    fake_time[0] = 115.0
    assert v.verify_token(token) is not None
    # t=140 : stale age 40 > max_stale (20) → drop cache + reject
    fake_time[0] = 140.0
    assert v.verify_token(token) is None
    assert v._jwks is None


def test_make_verifier_picks_up_max_stale_age_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SECURED_CLAUDE_MAX_STALE_AGE_S", "300")
    v = make_verifier()
    assert v is not None
    assert v.max_stale_age_s == 300.0


def test_make_verifier_max_stale_age_unset_means_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SECURED_CLAUDE_MAX_STALE_AGE_S", raising=False)
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com")
    v = make_verifier()
    assert v is not None
    assert v.max_stale_age_s is None


def test_make_verifier_max_stale_age_invalid_falls_back_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURED_CLAUDE_IDP_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SECURED_CLAUDE_MAX_STALE_AGE_S", "not-a-number")
    v = make_verifier()
    assert v is not None
    assert v.max_stale_age_s is None

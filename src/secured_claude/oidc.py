"""OIDC discovery + JWT validation (ADR-0038).

The v0.5 PrincipalProvider abstraction lets the broker pull principals
from a URL ; v0.6.0 (ADR-0037) added bearer auth + TTL cache on that
fetch. This module closes the second half of the OIDC story : when an
agent presents a JWT in its `/check` request, the broker verifies the
signature against the IdP's JWKS, checks `iss` + `exp`, and derives
the `principal_id` from the `sub` claim. Any failure → DENY immediately
(audit row written, Cerbos not even consulted).

Discovery is on-demand : the first JWT to hit the broker triggers a
fetch of `<issuer>/.well-known/openid-configuration` to find
`jwks_uri`, then a fetch of the JWKS itself. Both URLs cache for
`jwks_cache_ttl_s` seconds (default 3600 = 1 hour) — JWKS rotations
are infrequent, and cache misses cost an extra HTTP roundtrip per
token verification, which would be unacceptable per-tool-call.

Operator config :
  * SECURED_CLAUDE_IDP_ISSUER — canonical issuer URL (e.g. https://
    auth0.tenant.com/). Activates JWT verification when set ; a token
    presented WITHOUT issuer config is silently ignored (broker
    falls back to env-based principal_id).
  * SECURED_CLAUDE_OIDC_JWKS_TTL_S — JWKS cache lifetime (default 3600).
  * SECURED_CLAUDE_OIDC_AUDIENCE — optional `aud` claim to enforce
    (default : skip aud check).

Fail-closed semantics : any signature / `iss` / `exp` / `aud` / clock
violation returns `None` from `verify_token()`. The caller (broker
/check) then DENYs and writes an audit row. There is no "verify
best-effort" path — a presented token is either valid or rejected.

Bearer auth on the JWKS fetch : reuses the same SECURED_CLAUDE_IDP_
BEARER_TOKEN env from ADR-0037. Most public OIDC providers serve the
JWKS unauthenticated, but for internal IdPs the bearer header is
applied to JWKS requests as well.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import jwt
import requests
from jwt import PyJWK
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    PyJWTError,
)

from secured_claude import metrics

log = logging.getLogger(__name__)


class OIDCVerifier:
    """Verify JWTs against an OIDC issuer's JWKS, with TTL caching.

    Thread-safety : NOT thread-safe. The broker is single-process under
    uvicorn (one worker) so a single instance is shared across requests
    and access is serialised by FastAPI's event loop. Multi-worker
    deployments would need a lock around the cache invalidation path.
    """

    def __init__(
        self,
        issuer: str,
        audience: str | None = None,
        jwks_cache_ttl_s: float = 3600.0,
        timeout_s: float = 5.0,
        bearer_token: str | None = None,
        max_stale_age_s: float | None = None,
        client_cert_path: str | None = None,
        client_key_path: str | None = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_cache_ttl_s = jwks_cache_ttl_s
        self.timeout_s = timeout_s
        self.bearer_token = bearer_token
        # ADR-0039 — when set, stale JWKS / discovery older than this drops
        # back to reject (verify_token returns None). None = no max
        # (the v0.6.1 behaviour).
        self.max_stale_age_s = max_stale_age_s
        # ADR-0040 — mTLS client cert/key pair (both required) on the
        # discovery + JWKS fetches. Either-only is treated as not configured.
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self._discovery: dict[str, Any] | None = None
        self._discovery_ts: float = 0.0
        self._jwks: dict[str, Any] | None = None
        self._jwks_ts: float = 0.0

    def _cert_kwarg(self) -> tuple[str, str] | None:
        if self.client_cert_path and self.client_key_path:
            return (self.client_cert_path, self.client_key_path)
        return None

    def _now(self) -> float:
        # Indirection so tests can monkeypatch time.
        import time

        return time.monotonic()

    def _too_stale(self, ts: float, label: str) -> bool:
        """If max_stale_age_s is set and `ts` is older than it, return True.

        Helper for the stale-on-error fallback paths. Caller drops the cache
        and falls back (None) when this returns True.
        """
        if self.max_stale_age_s is None or ts == 0.0:
            return False
        age = self._now() - ts
        if age > self.max_stale_age_s:
            log.warning(
                "OIDC %s cache age %.1fs > max_stale_age %.1fs ; dropping",
                label,
                age,
                self.max_stale_age_s,
            )
            return True
        return False

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers

    def _get_discovery(self) -> dict[str, Any] | None:
        """Fetch + cache /.well-known/openid-configuration. Returns None on error."""
        if (
            self._discovery is not None
            and (self._now() - self._discovery_ts) < self.jwks_cache_ttl_s
        ):
            return self._discovery
        url = f"{self.issuer}/.well-known/openid-configuration"
        try:
            resp = requests.get(
                url, timeout=self.timeout_s, headers=self._headers(), cert=self._cert_kwarg()
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            log.exception("OIDC discovery failed at %s", url)
            # Stale-on-error : serve the cached discovery doc IF it hasn't
            # aged past max_stale_age_s ; otherwise drop it (ADR-0039).
            if self._too_stale(self._discovery_ts, "discovery"):
                self._discovery = None
                self._discovery_ts = 0.0
            return self._discovery
        if not isinstance(data, dict) or "jwks_uri" not in data:
            log.warning("OIDC discovery at %s missing jwks_uri ; ignoring", url)
            if self._too_stale(self._discovery_ts, "discovery"):
                self._discovery = None
                self._discovery_ts = 0.0
            return self._discovery
        self._discovery = data
        self._discovery_ts = self._now()
        return self._discovery

    def _get_jwks(self) -> dict[str, Any] | None:
        """Fetch + cache the JWKS via requests (so it's mockable in tests)."""
        if self._jwks is not None and (self._now() - self._jwks_ts) < self.jwks_cache_ttl_s:
            return self._jwks
        discovery = self._get_discovery()
        if discovery is None:
            return self._jwks  # serve stale on discovery error
        jwks_uri = str(discovery.get("jwks_uri") or "")
        if not jwks_uri:
            return self._jwks
        try:
            with metrics.JWKS_FETCH_DURATION_SECONDS.time():
                resp = requests.get(
                    jwks_uri,
                    timeout=self.timeout_s,
                    headers=self._headers(),
                    cert=self._cert_kwarg(),
                )
                resp.raise_for_status()
                data = resp.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            log.exception("OIDC JWKS fetch failed at %s", jwks_uri)
            metrics.JWKS_FETCH_TOTAL.labels(outcome="error").inc()
            # Stale-on-error : serve cached JWKS IF not too old (ADR-0039).
            if self._too_stale(self._jwks_ts, "jwks"):
                self._jwks = None
                self._jwks_ts = 0.0
                metrics.JWKS_STALE_DROPPED_TOTAL.inc()
            return self._jwks
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            if self._too_stale(self._jwks_ts, "jwks"):
                self._jwks = None
                self._jwks_ts = 0.0
                metrics.JWKS_STALE_DROPPED_TOTAL.inc()
            return self._jwks
        metrics.JWKS_FETCH_TOTAL.labels(outcome="success").inc()
        self._jwks = data
        self._jwks_ts = self._now()
        return self._jwks

    def _resolve_signing_key(self, token: str) -> Any | None:
        """Look up the public key in the JWKS for the token's `kid`."""
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError:
            return None
        kid = header.get("kid")
        jwks = self._get_jwks()
        if jwks is None:
            return None
        keys = jwks.get("keys") or []
        for jwk_data in keys:
            if not isinstance(jwk_data, dict):
                continue
            if kid is None or jwk_data.get("kid") == kid:
                try:
                    return PyJWK(jwk_data).key
                except (PyJWTError, ValueError):
                    continue
        return None

    def verify_token(self, token: str) -> dict[str, Any] | None:
        """Verify the JWT and return its claims dict, or None if invalid.

        Validates : signature, `iss` matches configured issuer, `exp`
        not past, `aud` matches configured audience (if set). Uses the
        IdP's JWKS via OIDC discovery.
        """
        # ADR-0043 — observe verify_token latency (sig + iss + exp + aud + kid).
        with metrics.JWT_VERIFY_DURATION_SECONDS.time():
            return self._verify_token_inner(token)

    def _verify_token_inner(self, token: str) -> dict[str, Any] | None:
        if not token:
            metrics.JWT_VERIFY_TOTAL.labels(outcome="rejected_other").inc()
            return None
        signing_key = self._resolve_signing_key(token)
        if signing_key is None:
            log.warning("OIDC : could not resolve signing key for token")
            metrics.JWT_VERIFY_TOTAL.labels(outcome="rejected_signature").inc()
            return None
        options: dict[str, Any] = {}
        decode_kwargs: dict[str, Any] = {
            "key": signing_key,
            "algorithms": ["RS256", "ES256", "RS384", "RS512", "ES384", "ES512"],
            "issuer": self.issuer,
            "options": options,
        }
        if self.audience is not None:
            decode_kwargs["audience"] = self.audience
        else:
            options["verify_aud"] = False
        try:
            claims: dict[str, Any] = jwt.decode(token, **decode_kwargs)
        except ExpiredSignatureError:
            metrics.JWT_VERIFY_TOTAL.labels(outcome="rejected_exp").inc()
            log.exception("OIDC : JWT expired")
            return None
        except InvalidIssuerError:
            metrics.JWT_VERIFY_TOTAL.labels(outcome="rejected_iss").inc()
            log.exception("OIDC : JWT iss mismatch")
            return None
        except InvalidAudienceError:
            metrics.JWT_VERIFY_TOTAL.labels(outcome="rejected_aud").inc()
            log.exception("OIDC : JWT aud mismatch")
            return None
        except InvalidSignatureError:
            metrics.JWT_VERIFY_TOTAL.labels(outcome="rejected_signature").inc()
            log.exception("OIDC : JWT signature invalid")
            return None
        except PyJWTError:
            metrics.JWT_VERIFY_TOTAL.labels(outcome="rejected_other").inc()
            log.exception("OIDC : JWT validation failed")
            return None
        metrics.JWT_VERIFY_TOTAL.labels(outcome="accepted").inc()
        return claims


class MultiIssuerVerifier:
    """Multi-issuer wrapper around N OIDCVerifiers (ADR-0041).

    Holds an allowlist of OIDCVerifiers keyed by issuer. On `verify_token`,
    extracts the unverified `iss` claim from the token, looks up the matching
    verifier in the allowlist, and delegates the full validation to it. If
    `iss` is missing or not in the allowlist → reject (None) without
    consulting any verifier — fail-closed by allowlist.

    Single-issuer deployments do NOT need this wrapper ; `make_verifier()`
    returns a bare OIDCVerifier when only one issuer is configured.

    Both classes (OIDCVerifier + MultiIssuerVerifier) expose the same
    `verify_token(token: str) -> dict | None` shape so the broker /check
    route doesn't care which it's holding.
    """

    def __init__(self, verifiers: list[OIDCVerifier]) -> None:
        if not verifiers:
            raise ValueError("MultiIssuerVerifier requires at least one verifier")
        self._by_issuer: dict[str, OIDCVerifier] = {v.issuer: v for v in verifiers}
        self.issuers: list[str] = list(self._by_issuer.keys())

    def verify_token(self, token: str) -> dict[str, Any] | None:
        if not token:
            metrics.MULTI_ISSUER_ROUTING_TOTAL.labels(outcome="rejected_no_iss").inc()
            return None
        try:
            unverified: dict[str, Any] = jwt.decode(
                token, options={"verify_signature": False, "verify_aud": False}
            )
        except PyJWTError:
            metrics.MULTI_ISSUER_ROUTING_TOTAL.labels(outcome="rejected_no_iss").inc()
            return None
        iss = str(unverified.get("iss") or "").rstrip("/")
        verifier = self._by_issuer.get(iss)
        if verifier is None:
            log.warning("OIDC : token iss=%r not in allowlist %s", iss, self.issuers)
            metrics.MULTI_ISSUER_ROUTING_TOTAL.labels(outcome="rejected_iss_not_in_allowlist").inc()
            return None
        metrics.MULTI_ISSUER_ROUTING_TOTAL.labels(outcome="routed").inc()
        return verifier.verify_token(token)


def _parse_issuer_env(raw: str) -> list[str]:
    """Parse SECURED_CLAUDE_IDP_ISSUER : single or comma-separated allowlist."""
    return [s.strip().rstrip("/") for s in raw.split(",") if s.strip()]


def _parse_idp_config_env(raw: str) -> list[dict[str, Any]] | None:
    """Parse SECURED_CLAUDE_IDP_CONFIG (JSON list) for per-issuer overrides (ADR-0044).

    Schema :
      [{"issuer": "https://a", "audience": "app1", "bearer_token": "tok1",
        "client_cert_path": "/etc/ssl/a.crt", "client_key_path": "/etc/ssl/a.key",
        "jwks_cache_ttl_s": 600, "max_stale_age_s": 1800, "timeout_s": 5},
       {"issuer": "https://b", "audience": "app2"}]

    All fields except `issuer` are optional ; missing fields fall back to the
    shared SECURED_CLAUDE_* env defaults at make_verifier() time.

    Returns None if the env is unset / empty / malformed (caller falls back
    to SECURED_CLAUDE_IDP_ISSUER + shared envs — the v0.7.1 behaviour).
    """
    if not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("SECURED_CLAUDE_IDP_CONFIG is not valid JSON ; ignoring")
        return None
    if not isinstance(data, list):
        log.warning("SECURED_CLAUDE_IDP_CONFIG must be a JSON list of objects ; ignoring")
        return None
    out: list[dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict) or not entry.get("issuer"):
            log.warning(
                "SECURED_CLAUDE_IDP_CONFIG entry missing required `issuer` field ; skipping"
            )
            continue
        out.append(entry)
    if not out:
        return None
    return out


def make_verifier() -> OIDCVerifier | MultiIssuerVerifier | None:
    """Factory : build a verifier from env, or None if not configured.

    Resolution order (first match wins) :
      1. SECURED_CLAUDE_IDP_CONFIG (JSON list, ADR-0044) — per-issuer
         audience / bearer / mTLS / TTL overrides. Each list entry is a
         standalone OIDCVerifier config ; multi-tenant SaaS with mixed-auth
         needs uses this.
      2. SECURED_CLAUDE_IDP_ISSUER set + non-empty → activate. Comma-separated
         values become a multi-issuer ALLOWLIST (ADR-0041) ; the broker accepts
         tokens from any of the listed issuers. All issuers share the rest of
         the SECURED_CLAUDE_* config (audience / bearer / mTLS / TTL).

    Shared envs (used when SECURED_CLAUDE_IDP_CONFIG is unset, OR as fallback
    defaults for fields missing from a per-issuer JSON entry) :
      * SECURED_CLAUDE_OIDC_AUDIENCE — optional aud claim.
      * SECURED_CLAUDE_OIDC_JWKS_TTL_S — JWKS cache lifetime.
      * SECURED_CLAUDE_IDP_TIMEOUT_S — HTTP timeout.
      * SECURED_CLAUDE_IDP_BEARER_TOKEN — optional bearer header on JWKS fetch.
      * SECURED_CLAUDE_MAX_STALE_AGE_S — max stale-on-error age (ADR-0039).
      * SECURED_CLAUDE_IDP_CLIENT_CERT_PATH + SECURED_CLAUDE_IDP_CLIENT_KEY_PATH —
        mTLS client cert/key pair (ADR-0040).

    None means JWT verification is disabled — broker falls back to the
    env-based principal_id (the v0.5 / v0.6.0 behaviour).

    Single-issuer config returns a bare OIDCVerifier. Multi-issuer config
    returns a MultiIssuerVerifier wrapping N single-issuer instances. Both
    share the verify_token signature so callers don't care which they hold.
    """
    # Shared defaults (read once, used both as standalone config + as
    # fallback when a per-issuer JSON entry omits a field).
    audience_default = os.environ.get("SECURED_CLAUDE_OIDC_AUDIENCE", "").strip() or None
    ttl_str = os.environ.get("SECURED_CLAUDE_OIDC_JWKS_TTL_S", "3600.0")
    try:
        ttl_default = float(ttl_str)
    except ValueError:
        ttl_default = 3600.0
    timeout_str = os.environ.get("SECURED_CLAUDE_IDP_TIMEOUT_S", "5.0")
    try:
        timeout_default = float(timeout_str)
    except ValueError:
        timeout_default = 5.0
    bearer_default = os.environ.get("SECURED_CLAUDE_IDP_BEARER_TOKEN", "").strip() or None
    max_stale_raw = os.environ.get("SECURED_CLAUDE_MAX_STALE_AGE_S", "").strip()
    max_stale_default: float | None = None
    if max_stale_raw:
        try:
            max_stale_default = float(max_stale_raw)
        except ValueError:
            max_stale_default = None
    cert_default = os.environ.get("SECURED_CLAUDE_IDP_CLIENT_CERT_PATH", "").strip() or None
    key_default = os.environ.get("SECURED_CLAUDE_IDP_CLIENT_KEY_PATH", "").strip() or None

    # Resolution path 1 (ADR-0044) : per-issuer JSON config wins.
    config_raw = os.environ.get("SECURED_CLAUDE_IDP_CONFIG", "")
    per_issuer = _parse_idp_config_env(config_raw)
    if per_issuer is not None:
        verifiers = [
            OIDCVerifier(
                issuer=str(entry["issuer"]),
                audience=entry.get("audience", audience_default),
                jwks_cache_ttl_s=float(entry.get("jwks_cache_ttl_s", ttl_default)),
                timeout_s=float(entry.get("timeout_s", timeout_default)),
                bearer_token=entry.get("bearer_token", bearer_default),
                max_stale_age_s=entry.get("max_stale_age_s", max_stale_default),
                client_cert_path=entry.get("client_cert_path", cert_default),
                client_key_path=entry.get("client_key_path", key_default),
            )
            for entry in per_issuer
        ]
        if len(verifiers) == 1:
            return verifiers[0]
        return MultiIssuerVerifier(verifiers)

    # Resolution path 2 (ADR-0041) : SECURED_CLAUDE_IDP_ISSUER + shared envs.
    issuer_raw = os.environ.get("SECURED_CLAUDE_IDP_ISSUER", "")
    issuers = _parse_issuer_env(issuer_raw)
    if not issuers:
        return None
    verifiers = [
        OIDCVerifier(
            issuer=iss,
            audience=audience_default,
            jwks_cache_ttl_s=ttl_default,
            timeout_s=timeout_default,
            bearer_token=bearer_default,
            max_stale_age_s=max_stale_default,
            client_cert_path=cert_default,
            client_key_path=key_default,
        )
        for iss in issuers
    ]
    if len(verifiers) == 1:
        return verifiers[0]
    return MultiIssuerVerifier(verifiers)


__all__ = ["MultiIssuerVerifier", "OIDCVerifier", "make_verifier"]

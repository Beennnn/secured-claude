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
from jwt.exceptions import PyJWTError

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
            # Stale-on-error : serve cached JWKS IF not too old (ADR-0039).
            if self._too_stale(self._jwks_ts, "jwks"):
                self._jwks = None
                self._jwks_ts = 0.0
            return self._jwks
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            if self._too_stale(self._jwks_ts, "jwks"):
                self._jwks = None
                self._jwks_ts = 0.0
            return self._jwks
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
        if not token:
            return None
        signing_key = self._resolve_signing_key(token)
        if signing_key is None:
            log.warning("OIDC : could not resolve signing key for token")
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
        except PyJWTError:
            log.exception("OIDC : JWT validation failed")
            return None
        return claims


def make_verifier() -> OIDCVerifier | None:
    """Factory : build a verifier from env, or None if not configured.

    Resolution :
      * SECURED_CLAUDE_IDP_ISSUER set + non-empty → activate.
      * SECURED_CLAUDE_OIDC_AUDIENCE — optional aud claim.
      * SECURED_CLAUDE_OIDC_JWKS_TTL_S — JWKS cache lifetime.
      * SECURED_CLAUDE_IDP_TIMEOUT_S — HTTP timeout (shared with HTTPPrincipalProvider).
      * SECURED_CLAUDE_IDP_BEARER_TOKEN — optional bearer header on JWKS fetch.
      * SECURED_CLAUDE_MAX_STALE_AGE_S — max stale-on-error age (None = unbounded ; ADR-0039).
      * SECURED_CLAUDE_IDP_CLIENT_CERT_PATH + SECURED_CLAUDE_IDP_CLIENT_KEY_PATH —
        mTLS client cert/key pair (both required ; ADR-0040).

    None means JWT verification is disabled — broker falls back to the
    env-based principal_id (the v0.5 / v0.6.0 behaviour).
    """
    issuer = os.environ.get("SECURED_CLAUDE_IDP_ISSUER", "").strip()
    if not issuer:
        return None
    audience = os.environ.get("SECURED_CLAUDE_OIDC_AUDIENCE", "").strip() or None
    ttl_str = os.environ.get("SECURED_CLAUDE_OIDC_JWKS_TTL_S", "3600.0")
    try:
        ttl = float(ttl_str)
    except ValueError:
        ttl = 3600.0
    timeout_str = os.environ.get("SECURED_CLAUDE_IDP_TIMEOUT_S", "5.0")
    try:
        timeout = float(timeout_str)
    except ValueError:
        timeout = 5.0
    bearer = os.environ.get("SECURED_CLAUDE_IDP_BEARER_TOKEN", "").strip() or None
    max_stale_raw = os.environ.get("SECURED_CLAUDE_MAX_STALE_AGE_S", "").strip()
    max_stale: float | None = None
    if max_stale_raw:
        try:
            max_stale = float(max_stale_raw)
        except ValueError:
            max_stale = None
    cert_path = os.environ.get("SECURED_CLAUDE_IDP_CLIENT_CERT_PATH", "").strip() or None
    key_path = os.environ.get("SECURED_CLAUDE_IDP_CLIENT_KEY_PATH", "").strip() or None
    return OIDCVerifier(
        issuer=issuer,
        audience=audience,
        jwks_cache_ttl_s=ttl,
        timeout_s=timeout,
        bearer_token=bearer,
        max_stale_age_s=max_stale,
        client_cert_path=cert_path,
        client_key_path=key_path,
    )


__all__ = ["OIDCVerifier", "make_verifier"]

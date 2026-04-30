"""Principal provider abstraction (ADR-0034).

The v0.3.1 gateway loaded principals from a static YAML file
(`config/principals.yaml`). v0.5 introduces a `PrincipalProvider`
abstraction with two concrete implementations :

- `YAMLPrincipalProvider` — the v0.3.1 behaviour, file-based.
- `HTTPPrincipalProvider` — fetches principals from a URL (JSON
  response, same schema as the YAML file).

The HTTP provider is the v0.5 foundation for future external-IdP
integration (Auth0, Keycloak, generic OIDC). v0.6+ ADRs will extend
this with proper OIDC discovery + JWT validation in the broker's
`/check` flow ; v0.5 ships only the URL-based principals fetch with
fail-open semantics.

Both providers return the same `{principal_id: {roles, attributes}}`
mapping shape that `gateway.make_app()` consumes.
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import requests
import yaml

log = logging.getLogger(__name__)

# Default principal — both `agent` and `claude_agent` per Cerbos's
# parentRoles semantics (see config/principals.yaml header comment +
# ADR-0033). Mirrored from `gateway._DEFAULT_PRINCIPAL` to keep this
# module self-contained.
DEFAULT_PRINCIPAL_ID = "claude-code-default"
DEFAULT_PRINCIPAL: dict[str, Any] = {
    "roles": ["agent", "claude_agent"],
    "attributes": {"trust_level": 0},
}


def _normalise_entry(entry: Any) -> dict[str, Any] | None:
    """Coerce a raw entry into {roles: list[str], attributes: dict}.

    Returns None if the entry is malformed (silently dropped). Both providers
    use this so YAML-vs-HTTP behaviour stays identical.
    """
    if not isinstance(entry, dict):
        return None
    roles = entry.get("roles") or ["agent"]
    attributes = entry.get("attributes") or {}
    if not isinstance(roles, list) or not isinstance(attributes, dict):
        return None
    return {
        "roles": [str(r) for r in roles],
        "attributes": dict(attributes),
    }


def _ensure_default(out: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Guarantee DEFAULT_PRINCIPAL_ID is in the output map."""
    if DEFAULT_PRINCIPAL_ID not in out:
        out[DEFAULT_PRINCIPAL_ID] = DEFAULT_PRINCIPAL
    return out


def _fallback() -> dict[str, dict[str, Any]]:
    """Single-default-only fallback (matches pre-v0.3.1 hardcoded behaviour)."""
    return {DEFAULT_PRINCIPAL_ID: DEFAULT_PRINCIPAL}


class PrincipalProvider(ABC):
    """Loads {principal_id → {roles, attributes}} from some source."""

    @abstractmethod
    def load(self) -> dict[str, dict[str, Any]]:
        """Return the principal directory. Always fail-open : on any error,
        return the single-default fallback (matches pre-v0.3.1 broker)."""
        raise NotImplementedError


class YAMLPrincipalProvider(PrincipalProvider):
    """Loads principals from a local YAML file (v0.3.1 default)."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            log.info("principals file %s not found ; using single-default fallback", self.path)
            return _fallback()
        try:
            data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            log.exception("principals file %s is malformed YAML ; using fallback", self.path)
            return _fallback()
        return _parse_principals_dict(data, source=str(self.path))


class HTTPPrincipalProvider(PrincipalProvider):
    """Fetches principals from a URL (JSON or YAML body, same schema).

    URL response shape matches `config/principals.yaml` :

        {"principals": {"<principal-id>": {"roles": [...], "attributes": {...}}}}

    On any HTTP / parse error, returns the single-default fallback. Caller
    receives no error ; only the broker logs the issue. This matches the
    YAML provider's fail-open semantics + the broker contract from ADR-0027.

    v0.6 (ADR-0037) — adds:
      * TTL cache : within the lifetime of the provider, repeat `load()`
        calls within `cache_ttl_s` seconds reuse the previous response.
        After the TTL expires, the next `load()` re-fetches.
      * Bearer auth : optional `bearer_token` is sent as
        `Authorization: Bearer <token>` so the IdP URL can sit behind
        an authenticated endpoint.
      * Stale-on-error : if the upstream IdP returns 5xx / unreachable
        AND we have a cached response, return the stale cache rather
        than the single-default fallback. Trades freshness for
        availability — operators with central-IdP outages get the last
        known-good directory instead of a degraded default.
    """

    def __init__(
        self,
        url: str,
        timeout_s: float = 5.0,
        cache_ttl_s: float = 300.0,
        bearer_token: str | None = None,
    ) -> None:
        self.url = url
        self.timeout_s = timeout_s
        self.cache_ttl_s = cache_ttl_s
        self.bearer_token = bearer_token
        self._cache: dict[str, dict[str, Any]] | None = None
        self._cache_ts: float = 0.0

    def _now(self) -> float:
        # Indirection so tests can monkeypatch time.
        import time

        return time.monotonic()

    def load(self) -> dict[str, dict[str, Any]]:
        # Cache hit : within TTL, reuse the last successful response.
        if self._cache is not None and (self._now() - self._cache_ts) < self.cache_ttl_s:
            return self._cache

        headers: dict[str, str] = {}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        try:
            resp = requests.get(self.url, timeout=self.timeout_s, headers=headers)
            resp.raise_for_status()
        except requests.RequestException:
            log.exception("principals URL %s unreachable", self.url)
            # Stale-on-error : prefer the last known-good cache over a
            # default-only fallback. Loud log so operators know.
            if self._cache is not None:
                log.warning(
                    "principals URL %s unreachable ; serving stale cache (age %.1fs)",
                    self.url,
                    self._now() - self._cache_ts,
                )
                return self._cache
            return _fallback()

        # Accept JSON or YAML — same parse path either way.
        body = resp.text
        try:
            # JSON first (faster + stricter) ; fall back to YAML.
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = yaml.safe_load(body) or {}
        except yaml.YAMLError:
            log.exception(
                "principals URL %s body is neither valid JSON nor valid YAML ; using fallback",
                self.url,
            )
            if self._cache is not None:
                return self._cache
            return _fallback()

        parsed = _parse_principals_dict(data, source=self.url)
        # Cache successful responses only. A fallback (e.g. response was
        # 200 OK but the body had no `principals:` key) bypasses the cache
        # so the next call retries.
        if parsed != _fallback():
            self._cache = parsed
            self._cache_ts = self._now()
        return parsed


def _parse_principals_dict(data: Any, *, source: str) -> dict[str, dict[str, Any]]:
    """Common parser for both YAML and HTTP providers."""
    if not isinstance(data, dict):
        log.warning("principals %s top-level not a mapping ; using fallback", source)
        return _fallback()
    raw = data.get("principals")
    if not isinstance(raw, dict):
        log.warning("principals %s missing `principals:` key ; using fallback", source)
        return _fallback()
    out: dict[str, dict[str, Any]] = {}
    for pid, entry in raw.items():
        normalised = _normalise_entry(entry)
        if normalised is not None:
            out[str(pid)] = normalised
    return _ensure_default(out)


def make_provider() -> PrincipalProvider:
    """Factory that picks the right provider from env config.

    Resolution order :
      1. SECURED_CLAUDE_IDP_URL set + non-empty → HTTPPrincipalProvider
         * SECURED_CLAUDE_IDP_TIMEOUT_S — request timeout (default 5.0)
         * SECURED_CLAUDE_IDP_CACHE_TTL_S — cache lifetime (default 300)
         * SECURED_CLAUDE_IDP_BEARER_TOKEN — Authorization: Bearer <token>
      2. SECURED_CLAUDE_PRINCIPALS env or default config/principals.yaml
         → YAMLPrincipalProvider
    """
    url = os.environ.get("SECURED_CLAUDE_IDP_URL", "").strip()
    if url:
        timeout_str = os.environ.get("SECURED_CLAUDE_IDP_TIMEOUT_S", "5.0")
        try:
            timeout = float(timeout_str)
        except ValueError:
            timeout = 5.0
        ttl_str = os.environ.get("SECURED_CLAUDE_IDP_CACHE_TTL_S", "300.0")
        try:
            ttl = float(ttl_str)
        except ValueError:
            ttl = 300.0
        bearer = os.environ.get("SECURED_CLAUDE_IDP_BEARER_TOKEN", "").strip() or None
        return HTTPPrincipalProvider(
            url,
            timeout_s=timeout,
            cache_ttl_s=ttl,
            bearer_token=bearer,
        )
    yaml_path = Path(os.environ.get("SECURED_CLAUDE_PRINCIPALS", "config/principals.yaml"))
    return YAMLPrincipalProvider(yaml_path)


__all__ = [
    "DEFAULT_PRINCIPAL",
    "DEFAULT_PRINCIPAL_ID",
    "HTTPPrincipalProvider",
    "PrincipalProvider",
    "YAMLPrincipalProvider",
    "make_provider",
]

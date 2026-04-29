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

    v0.5 limitation : the broker does NOT cache the result. Every gateway
    startup hits the URL once. v0.6 ticket : add a TTL-based cache so a
    cold-startup burst doesn't hammer the IdP.
    """

    def __init__(self, url: str, timeout_s: float = 5.0) -> None:
        self.url = url
        self.timeout_s = timeout_s

    def load(self) -> dict[str, dict[str, Any]]:
        try:
            resp = requests.get(self.url, timeout=self.timeout_s)
            resp.raise_for_status()
        except requests.RequestException:
            log.exception("principals URL %s unreachable ; using single-default fallback", self.url)
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
            return _fallback()
        return _parse_principals_dict(data, source=self.url)


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
        return HTTPPrincipalProvider(url, timeout_s=timeout)
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

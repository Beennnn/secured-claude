"""Cerbos PDP HTTP client (ADR-0001).

Calls /api/check/resources on the Cerbos sidecar to evaluate authorization.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import requests


@dataclass(frozen=True)
class CheckResult:
    """Result of a Cerbos CheckResources call."""

    allow: bool
    reason: str
    duration_ms: int
    raw: dict[str, Any]


class CerbosClient:
    """Thin wrapper for the Cerbos /api/check/resources endpoint."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:3592",
        timeout: float = 2.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check(
        self,
        principal_id: str,
        principal_roles: list[str],
        principal_attr: dict[str, Any],
        resource_kind: str,
        resource_id: str,
        resource_attr: dict[str, Any],
        actions: list[str],
    ) -> CheckResult:
        """Evaluate the policy for `actions` and return the first action's decision."""
        body = {
            "requestId": f"sc-{int(time.time() * 1000)}",
            "principal": {
                "id": principal_id,
                "roles": principal_roles,
                "attr": principal_attr,
            },
            "resources": [
                {
                    "actions": actions,
                    "resource": {
                        "kind": resource_kind,
                        "id": resource_id,
                        "attr": resource_attr,
                    },
                }
            ],
        }

        t0 = time.perf_counter()
        resp = requests.post(
            f"{self.base_url}/api/check/resources",
            json=body,
            timeout=self.timeout,
        )
        duration_ms = int((time.perf_counter() - t0) * 1000)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()

        results = data.get("results", [])
        if not results:
            return CheckResult(False, "no result from Cerbos", duration_ms, data)
        first = results[0]
        actions_map = first.get("actions", {})
        action = actions[0]
        effect = actions_map.get(action, "EFFECT_DENY")
        allow = effect == "EFFECT_ALLOW"
        validation_errors = first.get("validationErrors") or []
        reason_parts = [f"effect={effect}"]
        if validation_errors:
            reason_parts.append(f"validation={validation_errors}")
        return CheckResult(allow, "; ".join(reason_parts), duration_ms, data)


__all__ = ["CerbosClient", "CheckResult"]

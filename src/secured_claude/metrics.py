"""Prometheus counters for operational signal (ADR-0042).

Every event the broker logs at WARNING / ERROR level (cache-drop, JWT-deny,
mTLS-rotation-partial, etc.) gets a corresponding counter here. Counters
expose at GET /metrics in the standard Prometheus text exposition format ;
operators scrape into Prometheus / VictoriaMetrics / Grafana Cloud and
build alerts on the rates.

Why counters, not log parsing :
  * Log scraping is fragile (format changes break alerts).
  * Counters are a stable contract — operators can build Grafana dashboards
    without parsing log lines.
  * Cardinality is fixed (no high-cardinality labels) so the counters
    don't blow up the time-series budget.

The counters use the project-wide `secured_claude_*` prefix so they
don't collide with any other Prometheus exporters running in the
same broker host process.

All counters are package-globals — the gateway imports them once at
startup, the providers + verifiers import them at module load. Tests
that need to check counter values inspect `<counter>._value.get()` or
use the Prometheus testing helpers.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, generate_latest

# Dedicated registry so tests can use the default Prometheus registry
# without leaking app counters between test invocations. The gateway
# exposes ONLY this registry on /metrics ; the default registry is left
# alone for libraries that auto-register their own metrics.
REGISTRY = CollectorRegistry(auto_describe=True)


# ────────────────────────────────────────────────────────────────────
# HTTPPrincipalProvider counters (ADR-0037 / ADR-0039 / ADR-0040)
# ────────────────────────────────────────────────────────────────────

PRINCIPALS_FETCH_TOTAL = Counter(
    "secured_claude_principals_fetch_total",
    "Total principals-endpoint fetch attempts (by outcome).",
    labelnames=("outcome",),  # success | error
    registry=REGISTRY,
)

PRINCIPALS_CACHE_HIT_TOTAL = Counter(
    "secured_claude_principals_cache_hit_total",
    "Principals cache hits within TTL — no HTTP roundtrip.",
    registry=REGISTRY,
)

PRINCIPALS_STALE_SERVED_TOTAL = Counter(
    "secured_claude_principals_stale_served_total",
    "Stale-on-error serves : upstream failed but cache was within max_stale_age.",
    registry=REGISTRY,
)

PRINCIPALS_STALE_DROPPED_TOTAL = Counter(
    "secured_claude_principals_stale_dropped_total",
    "Cache dropped past max_stale_age — falling back to single-default (ADR-0039).",
    registry=REGISTRY,
)

PRINCIPALS_FALLBACK_TOTAL = Counter(
    "secured_claude_principals_fallback_total",
    "First-load failures with no cache — single-default fallback served.",
    registry=REGISTRY,
)


# ────────────────────────────────────────────────────────────────────
# OIDCVerifier counters (ADR-0038 / ADR-0039 / ADR-0040)
# ────────────────────────────────────────────────────────────────────

JWT_VERIFY_TOTAL = Counter(
    "secured_claude_jwt_verify_total",
    "Total JWT verification attempts (by outcome).",
    labelnames=("outcome",),  # accepted | rejected_signature | rejected_iss
    # | rejected_exp | rejected_aud | rejected_other
    registry=REGISTRY,
)

JWKS_FETCH_TOTAL = Counter(
    "secured_claude_jwks_fetch_total",
    "Total JWKS endpoint fetch attempts (by outcome).",
    labelnames=("outcome",),  # success | error
    registry=REGISTRY,
)

JWKS_STALE_DROPPED_TOTAL = Counter(
    "secured_claude_jwks_stale_dropped_total",
    "JWKS cache dropped past max_stale_age — verify_token returns None (ADR-0039).",
    registry=REGISTRY,
)


# ────────────────────────────────────────────────────────────────────
# MultiIssuerVerifier counters (ADR-0041)
# ────────────────────────────────────────────────────────────────────

MULTI_ISSUER_ROUTING_TOTAL = Counter(
    "secured_claude_multi_issuer_routing_total",
    "Multi-issuer routing decisions (by outcome).",
    labelnames=("outcome",),  # routed | rejected_iss_not_in_allowlist | rejected_no_iss
    registry=REGISTRY,
)


# ────────────────────────────────────────────────────────────────────
# Gateway counters (ADR-0001 / ADR-0009)
# ────────────────────────────────────────────────────────────────────

CHECK_DECISIONS_TOTAL = Counter(
    "secured_claude_check_decisions_total",
    "Cerbos /check decisions (by outcome).",
    labelnames=("decision",),  # ALLOW | DENY | jwt_deny | cerbos_unavailable
    registry=REGISTRY,
)


def render() -> bytes:
    """Render the registry in Prometheus exposition format."""
    return generate_latest(REGISTRY)


def content_type() -> str:
    """Standard Prometheus text exposition Content-Type header value."""
    return "text/plain; version=0.0.4; charset=utf-8"


__all__ = [
    "CHECK_DECISIONS_TOTAL",
    "JWKS_FETCH_TOTAL",
    "JWKS_STALE_DROPPED_TOTAL",
    "JWT_VERIFY_TOTAL",
    "MULTI_ISSUER_ROUTING_TOTAL",
    "PRINCIPALS_CACHE_HIT_TOTAL",
    "PRINCIPALS_FALLBACK_TOTAL",
    "PRINCIPALS_FETCH_TOTAL",
    "PRINCIPALS_STALE_DROPPED_TOTAL",
    "PRINCIPALS_STALE_SERVED_TOTAL",
    "REGISTRY",
    "content_type",
    "render",
]

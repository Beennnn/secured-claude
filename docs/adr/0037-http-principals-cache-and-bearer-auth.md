# 37. TTL cache + bearer auth on HTTPPrincipalProvider

Date: 2026-04-30
Status: Accepted

## Context

[ADR-0034](0034-principal-provider-abstraction.md) shipped `HTTPPrincipalProvider` as the v0.5 foundation for IdP integration : the broker can pull principals from a URL instead of a static YAML file. v0.5 left two operational concerns explicitly deferred :

> "v0.5 limitation : the broker does NOT cache the result. Every gateway startup hits the URL once. v0.6 ticket : add a TTL-based cache so a cold-startup burst doesn't hammer the IdP."

> "v0.5 fetches the URL with no auth headers. If operators put their principals behind an authenticated endpoint, they need to pre-sign the URL or hit it via an authenticated proxy. v0.6+ ticket : `SECURED_CLAUDE_IDP_BEARER_TOKEN` env or mTLS."

Both tickets close in this ADR.

## Decision

### TTL cache

`HTTPPrincipalProvider.load()` now caches the parsed result for `cache_ttl_s` seconds (default 300 = 5 minutes). Within the TTL window, repeat `load()` calls return the cached dict without an HTTP roundtrip.

```python
HTTPPrincipalProvider(url, cache_ttl_s=300.0)
```

Operator override : `SECURED_CLAUDE_IDP_CACHE_TTL_S` env (defaults to 300, falls back to 300 if not parseable as float).

### Stale-on-error

If the upstream IdP returns 5xx OR is unreachable AND we have a cached response, the provider returns the **stale cache** instead of the single-default fallback. Trades freshness for availability — operators with a brief IdP outage get the last known-good directory instead of every session degrading to default.

The fallback path (single-default `claude-code-default`) only kicks in when there's no cache to fall back to (first-load failure).

### Bearer auth

`HTTPPrincipalProvider(url, bearer_token=...)` adds `Authorization: Bearer <token>` to every fetch.

```python
HTTPPrincipalProvider(url, bearer_token="abc-secret")
```

Operator override : `SECURED_CLAUDE_IDP_BEARER_TOKEN` env (treated as unset if empty / whitespace-only).

This unlocks two common IdP patterns :

1. **Authenticated webhook** — operator runs a small Lambda/Cloud Function that maps Auth0 / Okta / Keycloak users to the principals.yaml schema, sits behind an auth wall.
2. **Service-to-service** — broker ↔ IdP communication carries a service-account token verifiable on the IdP side.

mTLS support deferred to v0.7+ (needs `requests` cert kwargs + an env-based cert/key path pair). The bearer-token pattern covers ~80% of real-world IdP integrations.

### Caching behaviour matrix

```
   request → response                                    behaviour
   ─────────────────────────────────────────────────────────────────────
   cache miss + 200 OK + valid principals body         cache + return
   cache miss + 200 OK + invalid body                  fallback (no cache)
   cache miss + 5xx / unreachable                      fallback (no cache)
   cache hit (within TTL)                              return cached
   cache hit (TTL expired) + 200 OK                    refresh + return
   cache hit (TTL expired) + 5xx / unreachable         STALE cache (loud log)
```

The "fallback (no cache)" rows are deliberate — invalid responses don't pollute the cache. Re-fetching on the next `load()` gives the IdP a chance to recover without us having to wait for the TTL.

## Consequences

**Positive** :
- Operators can put their principals endpoint behind auth (Auth0 management API, GitHub Actions OIDC token, etc.) without exposing it publicly.
- A brief IdP outage no longer cascades to every session degrading to default principal.
- 9 new tests cover the cache-hit, TTL-expiry, stale-on-error, bearer-header, and env-resolution paths. Total now 161 tests (was 152 in v0.5.5).
- Backward-compatible : default `cache_ttl_s=300` + `bearer_token=None` matches v0.5.5 behaviour for existing deployments.

**Negative** :
- Cache means a principals change at the IdP takes up to 5 minutes to reflect at the broker. Operators can shorten via `SECURED_CLAUDE_IDP_CACHE_TTL_S` if needed.
- Stale-on-error means a permanent IdP misconfiguration (e.g. revoked token, deleted endpoint) keeps serving stale principals indefinitely. Mitigated by the loud `WARNING` log line on every stale serve — operators tailing logs see it. v0.7 ticket : optional max-stale-age that flips back to fallback after N minutes.

**Neutral** :
- The cache lives in the provider instance ; FastAPI's lifespan creates one provider per `make_app()` so there's exactly one cache per broker process. Restart = cache reset.

## Alternatives considered

- **Sliding TTL (refresh on access)** — bookkeeping complexity for marginal cache hit rate gain. Rejected — fixed TTL is operationally simpler.
- **Background refresh thread** — proactively re-fetches before TTL expiry. Adds threading + lifecycle to the provider. v0.7+ if request-latency-during-refresh becomes a concern. Rejected for v0.6.
- **Header-based cache control** (respect `Cache-Control` from the IdP response) — more sophisticated but couples to upstream IdP behaviour. Operators may not control the IdP's cache headers. Rejected for v0.6 ; the env knob is simpler.
- **Always-fail-open default** (no stale-on-error) — every IdP blip degrades to single-default. Worse availability. Rejected.

## Verification

Tests in `tests/test_principals.py` (9 new) :

- `test_http_provider_caches_within_ttl` — same dict returned, only 1 HTTP call
- `test_http_provider_refetches_after_ttl_expires` — 2 HTTP calls, fresh value
- `test_http_provider_serves_stale_on_5xx` — TTL expired + 5xx → stale cache, not fallback
- `test_http_provider_falls_back_when_no_cache_and_5xx` — first-load failure → fallback
- `test_http_provider_sends_bearer_token` — Authorization header present
- `test_http_provider_no_bearer_when_token_unset` — no Authorization header
- `test_make_provider_picks_up_cache_ttl_env` — env → cache_ttl_s
- `test_make_provider_picks_up_bearer_token_env` — env → bearer_token
- `test_make_provider_invalid_cache_ttl_falls_back_to_default` — non-numeric env → 300

End-to-end (manual) :

```bash
$ SECURED_CLAUDE_IDP_URL=http://idp.local/principals \
  SECURED_CLAUDE_IDP_BEARER_TOKEN=eyJh... \
  SECURED_CLAUDE_IDP_CACHE_TTL_S=60 \
  secured-claude up
$ # broker pulls principals once, caches for 60 s, sends Authorization header.
```

## References

- [ADR-0027](0027-multi-principal-directory.md) — principals directory contract (the data model)
- [ADR-0034](0034-principal-provider-abstraction.md) — provider abstraction this ADR extends
- v0.7 tickets :
  - mTLS auth (cert/key pair env)
  - max-stale-age + fallback-after-N-minutes
  - background refresh thread (if request latency on refresh becomes a concern)
- v0.6.1 ticket : JWT validation in `/check` (the agent presents a token, broker verifies against IdP JWKS)

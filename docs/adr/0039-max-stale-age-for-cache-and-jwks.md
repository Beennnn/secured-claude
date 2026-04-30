# 39. Max stale-age for principals cache + JWKS cache

Date: 2026-04-30
Status: Accepted

## Context

[ADR-0037](0037-http-principals-cache-and-bearer-auth.md) introduced stale-on-error semantics for `HTTPPrincipalProvider` : when the IdP returns 5xx or is unreachable AND we have a cached response, the provider serves the **stale cache** instead of the single-default fallback. [ADR-0038](0038-jwt-validation-and-oidc-discovery.md) applied the same pattern to `OIDCVerifier`'s discovery + JWKS fetches. Both ADRs explicitly flagged the resulting trade-off as a known limitation :

> "Permanent IdP misconfig (revoked token, deleted endpoint) keeps serving stale principals indefinitely. Mitigated by the loud `WARNING` log line on every stale serve — operators tailing logs see it. v0.7 ticket : optional max-stale-age that flips back to fallback after N minutes."

The mitigation works for **brief outages** (an IdP restart, a network blip, a regional cloud incident) where serving stale is strictly better than degrading every session to single-default. But it is silently wrong for **permanent misconfigurations** :

- IdP rotates its bearer token + the operator forgets to update `SECURED_CLAUDE_IDP_BEARER_TOKEN`.
- IdP retires the principals endpoint + the operator forgets to update `SECURED_CLAUDE_IDP_URL`.
- IdP rotates JWKS + the new key is signed with a different `kid` AND discovery breaks (rare but possible).

In all three cases, the WARNING log is emitted on every request, but the broker keeps serving the **last known-good directory + last known-good JWKS** indefinitely. An attacker who compromised the IdP at any point in the past would keep getting their principals served. A revoked principal stays valid until the broker process restarts.

## Decision

Both `HTTPPrincipalProvider` and `OIDCVerifier` gain an optional `max_stale_age_s: float | None = None` parameter. When set, a stale-on-error serve checks the cache age :

- **Within `max_stale_age_s`** → serve the stale cache (current ADR-0037 / ADR-0038 behaviour).
- **Past `max_stale_age_s`** → drop the cache, log a WARNING, and fall back to :
  - `_fallback()` (single-default) for `HTTPPrincipalProvider`
  - `None` (reject token) for `OIDCVerifier`

```python
HTTPPrincipalProvider(url, cache_ttl_s=300, max_stale_age_s=1800)
OIDCVerifier(issuer=..., jwks_cache_ttl_s=3600, max_stale_age_s=1800)
```

A single shared env knob `SECURED_CLAUDE_MAX_STALE_AGE_S` configures both providers' factories (`make_provider()` in principals.py + `make_verifier()` in oidc.py). The shared env is deliberate — a deployment that wants stale bounds on the principals directory almost always wants the same bound on JWKS.

`None` (the default + the env-unset case) preserves the v0.6.1 behaviour : stale forever. **Existing deployments unaffected.**

## How max_stale_age_s relates to cache_ttl_s

These two TTLs answer different questions :

- **`cache_ttl_s`** : "How long do I trust a *successful* response before re-fetching ?" — keeps the IdP from being hammered. Reset on every successful fetch.
- **`max_stale_age_s`** : "How long am I willing to serve a *failed* upstream's last good response ?" — caps the security blast radius of a permanent misconfig.

The relationship is a strict ordering : `max_stale_age_s ≥ cache_ttl_s` (otherwise the cache would be invalid before it's even past TTL — the operator can set this but it's typically a configuration error). We do not enforce the ordering at the API level — operators may have legitimate reasons for tight bounds during incident response.

Default recommendations :
- Demo / dev : `max_stale_age_s=None` (current behaviour ; no risk in non-prod).
- Production : `max_stale_age_s=1800` (30 min) — matches typical SLA-window expectations.
- Compliance-sensitive (banking, healthcare, public sector) : `max_stale_age_s=300` (5 min) — short enough that a revoked principal can't be served past a single page-and-fix cycle.

## Consequences

**Positive** :
- Closes the "permanent IdP misconfig serves compromised state forever" gap for both principals + JWKS.
- A revoked bearer token + restarted broker now eventually drops back to single-default + reject (instead of serving the last known-good directory until process restart).
- Compliance posture : operators can document the maximum window during which a revoked principal could be served, instead of "until next process restart".
- 9 new tests cover both modules : drop-on-max-exceed, stale-still-serves-within-bound, env wiring + 3 invalid-env paths. Total now 204 tests (was 195 in v0.6.1).
- Backward-compatible : default `max_stale_age_s=None` matches v0.6.1.

**Negative** :
- A misconfigured `max_stale_age_s` (set too tight) can produce false negatives during legitimate outages. Operators who set 60 s for "tight bound" will see degraded sessions during a 90 s IdP restart even though the stale data was perfectly valid.
- The shared env knob means operators can't independently bound principals vs JWKS staleness. If demand emerges, future ADR can split into 2 envs.

**Neutral** :
- The cache is dropped in-place when max-stale exceeds — the next call retries the IdP fresh, so a recovered IdP gets re-cached normally.
- No metric / alert hook : we emit a WARNING log on the drop event but don't push to a metrics backend. Future ADR can add a Prometheus counter.

## Alternatives considered

- **Stop serving stale entirely** (drop ADR-0037's stale-on-error). Rejected — the brief-outage case is the common one ; defaulting to fail-closed punishes operators for IdP hiccups.
- **Per-provider env knobs** (`SECURED_CLAUDE_PRINCIPALS_MAX_STALE_AGE_S` + `SECURED_CLAUDE_OIDC_MAX_STALE_AGE_S`). Rejected as YAGNI for v0.6.2 — operators almost always want the same bound on both. Easy to split later if demand emerges.
- **Configurable fallback target** (let operators pick "single-default" vs "fail-closed" vs "previous fallback"). Rejected — the right behaviour is unambiguous : principals fall back to single-default (matches the v0.6.0 pattern), JWKS falls back to reject (matches v0.6.1's fail-closed). Operators don't need a knob here.
- **Replace cache_ttl_s with a single max_stale_age_s** (collapse the 2 TTLs). Rejected — they answer different questions ; collapsing them would force operators to choose between cache-hit-rate and stale-bound.

## Verification

Tests in `tests/test_principals.py` (4 new) :

- `test_http_provider_drops_stale_cache_after_max_stale_age` — t=0 cache, t=15 stale-serve OK, t=35 drop + fallback
- `test_http_provider_max_stale_age_none_serves_forever` — None preserves v0.6.1 stale-forever
- `test_make_provider_picks_up_max_stale_age_env` — env activation
- `test_make_provider_max_stale_age_unset_means_none` — unset = None default
- `test_make_provider_max_stale_age_invalid_falls_back_to_none` — non-numeric env → None

Tests in `tests/test_oidc.py` (4 new) :

- `test_verifier_drops_stale_jwks_after_max_stale_age` — same shape as principals test
- `test_make_verifier_picks_up_max_stale_age_env` — env activation
- `test_make_verifier_max_stale_age_unset_means_none` — unset = None
- `test_make_verifier_max_stale_age_invalid_falls_back_to_none` — non-numeric env

End-to-end (manual) :

```bash
$ SECURED_CLAUDE_IDP_URL=https://idp.example.com/principals \
  SECURED_CLAUDE_IDP_BEARER_TOKEN=svc-token \
  SECURED_CLAUDE_IDP_ISSUER=https://idp.example.com \
  SECURED_CLAUDE_MAX_STALE_AGE_S=300 \
  secured-claude up
$ # Both principals + JWKS caches drop after 5 min of upstream failure ;
$ # broker logs the WARNING + falls back to single-default / reject.
```

## References

- [ADR-0037](0037-http-principals-cache-and-bearer-auth.md) — stale-on-error pattern (closes its v0.7 ticket)
- [ADR-0038](0038-jwt-validation-and-oidc-discovery.md) — JWKS stale handling (closes its v0.7 ticket)
- v0.7+ tickets :
  - mTLS auth on IdP URL (cert/key pair env)
  - Multi-issuer ALLOWLIST (accept tokens from N IdPs)
  - Background JWKS refresh thread (proactive re-fetch before TTL expiry)
  - Per-provider stale-age envs (split shared env) if demand emerges
  - Prometheus counter for stale-drop events

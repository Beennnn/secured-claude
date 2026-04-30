# 41. Multi-issuer ALLOWLIST for OIDC verification

Date: 2026-04-30
Status: Accepted (with scope-honesty addendum below)

## Scope honesty (added 2026-04-30 post-review)

**The "multi-tenant SaaS / M&A migration windows / hybrid cloud / DR failover" framing below is speculative for the project's actual use case.** `secured-claude` is a single-user dev tool ; the realistic deployment has ONE IdP (the user's Auth0 / Okta / GitHub login), not a federation of tenants the broker has to triage.

The wrapper-class implementation (`MultiIssuerVerifier` holding N `OIDCVerifier` instances) is ~50 lines and harmless when only one issuer is configured (factory returns the bare `OIDCVerifier` directly, the wrapper is never instantiated). Single-issuer deployments pay zero overhead.

What's left as honest framing : multi-issuer support is a clean extension point that doesn't break the existing API. The ADR's elaborate use-case justification (M&A, hybrid cloud, DR failover) describes patterns where this WOULD be useful — none of which the project itself targets.

## Context

[ADR-0038](0038-jwt-validation-and-oidc-discovery.md) shipped `OIDCVerifier` with a single configured issuer : the broker accepts JWTs whose `iss` claim equals exactly that one URL. This works for ~70 % of deployments — one organization, one IdP, one tenant.

The remaining 30 % needs **multi-issuer** :

- **Multi-tenant SaaS** : the broker serves N customers, each with their own Auth0 / Okta / Keycloak tenant. Different `iss`, different signing keys, but the broker accepts all of them.
- **Mergers / acquisitions** : organisation A acquires organisation B ; both IdPs co-exist for the duration of the migration window. Sometimes years.
- **Hybrid cloud** : workloads run in both the corporate AD-backed tenant AND a per-cloud-provider OIDC tenant (GitHub Actions, GCP Workload Identity, AWS IAM Roles Anywhere) ; tokens come from any of them depending on which environment minted them.
- **Disaster recovery** : a backup IdP exists for failover, with its own keys ; the broker accepts tokens from either primary or secondary.

ADR-0038's "v0.7+ multi-issuer ALLOWLIST" ticket was deferred specifically because it changes the verifier *shape* — single-issuer is "what does my issuer URL look like ?" while multi-issuer is "which of N issuers minted this token ?".

## Decision

A new `MultiIssuerVerifier` wraps N `OIDCVerifier` instances, one per allowed issuer. On `verify_token(token)` :

1. Decode the JWT **without** signature verification to extract the `iss` claim (same crypto-bypass-then-pin pattern PyJWT uses internally).
2. Look up the matching `OIDCVerifier` in the allowlist by `iss` (trailing slashes normalised away).
3. If `iss` is missing, malformed, or not in the allowlist → reject (None).
4. Otherwise, delegate the full validation (signature against the matched issuer's JWKS + `iss` + `exp` + `aud` + `kid`) to the matched verifier.

```python
from secured_claude.oidc import MultiIssuerVerifier, OIDCVerifier

multi = MultiIssuerVerifier([
    OIDCVerifier(issuer="https://tenant-a.auth0.com"),
    OIDCVerifier(issuer="https://tenant-b.auth0.com"),
])
multi.verify_token(token)  # routes to A or B based on iss claim
```

### Wrapper, not refactor

Two architectural options were considered :

1. **Refactor `OIDCVerifier`** to internally hold a list of issuers + per-issuer cache state. Pros : single class, public API stays simple (`OIDCVerifier(issuer=str | list[str])`). Cons : every internal method (`_get_discovery`, `_get_jwks`, `_resolve_signing_key`) needs an issuer arg ; existing tests that mutate `v._jwks_ts = 0.0` break ; back-compat shims for `_discovery_ts` and `_jwks_ts` get tangled.
2. **Wrapper class** that holds a `dict[issuer, OIDCVerifier]` and dispatches. Pros : zero changes to existing OIDCVerifier code, trivial to test, full back-compat. Cons : 2 verifier classes to keep in sync.

Chose option 2 — the wrapper. Single-issuer deployments still get a bare `OIDCVerifier` (no behavioural change), multi-issuer wraps it in `MultiIssuerVerifier`. The factory `make_verifier()` returns whichever fits :

```python
SECURED_CLAUDE_IDP_ISSUER="https://idp.example.com"           # → OIDCVerifier
SECURED_CLAUDE_IDP_ISSUER="https://a.com,https://b.com"        # → MultiIssuerVerifier
```

Both classes expose the same `verify_token(token: str) -> dict | None` shape so the broker `/check` route doesn't care which it's holding. The gateway type-hint is `OIDCVerifier | MultiIssuerVerifier | None`.

### Comma-separated env

`SECURED_CLAUDE_IDP_ISSUER` accepts a comma-separated list. Whitespace-tolerant ; trailing slashes normalised away ; empty entries silently dropped (so `a,,b` is `[a, b]`, not a parse error). Single-value behaviour is unchanged from v0.6.0.

### Iss-claim extraction is unverified-then-pinned

Step 1 (extract `iss` without signature verification) is a controlled pattern : we look up the matching verifier, but the **full** validation (including signature) happens in the matched verifier's `verify_token`. An attacker forging an `iss` claim to game the routing still has to sign with the matching issuer's actual key — which they don't have. The unverified extraction is purely a routing decision, not a trust decision.

## Consequences

**Positive** :
- Multi-tenant SaaS, M&A migration windows, hybrid cloud, DR failover all unlock with this rev.
- Zero changes to existing single-issuer OIDCVerifier code — behavioural diff only at the factory boundary.
- 11 new tests cover the new class : routing, allowlist enforcement, empty / garbage / no-iss tokens, env parsing (single + multi + trailing-slash + blank entries). Total now 227 tests (was 216 in v0.7.0).
- Backward-compatible : single-value env returns a bare OIDCVerifier (the v0.7.0 behaviour). Existing deployments unaffected.

**Negative** :
- Per-issuer JWKS caches are independent : N issuers = N HTTP calls to discover + N JWKS fetches on first use. For multi-tenant brokers with many tenants, this is a one-time cost on first request per tenant ; subsequent requests hit the per-tenant cache.
- Single shared `audience` / `bearer_token` / mTLS pair config across all issuers. Per-issuer overrides not supported in v0.7.1 — operators with mixed-auth needs (one IdP needs bearer on JWKS, another doesn't) need a future ADR.
- An attacker can probe which IdPs are in the allowlist by sending tokens with crafted `iss` claims and watching for the WARNING log line. Mitigation : log severity is WARNING, not INFO ; operators with stricter posture can rate-limit log emission.

**Neutral** :
- Each `OIDCVerifier` in the wrapper holds its own state (cache, mTLS config, max-stale tracking). Restart resets all of them.
- The wrapper class doesn't add lifecycle complexity — it's a pure dispatcher with no own state beyond the issuer→verifier map.

## Alternatives considered

- **Refactor OIDCVerifier in-place** (option 1 above) — tested locally and discarded due to back-compat shim complexity around `_jwks_ts` and `_discovery_ts` mutation in existing tests.
- **Per-issuer config blocks via JSON env** (`SECURED_CLAUDE_IDP_CONFIG=[{"issuer":"a","audience":"x"},...]`) — more flexible (per-issuer audience / bearer / mTLS) but parsing complexity + harder operator UX. Rejected for v0.7.1 ; future ADR if demand emerges.
- **Cerbos PDP-side multi-issuer routing** — Cerbos can match on token claims natively, but only after we've already validated the signature. The broker is the right place to do the routing because it owns the IdP integration ; Cerbos owns the policy.
- **Trust ALL issuers (no allowlist)** — i.e. accept any `iss` claim and discover its `jwks_uri` on the fly. Rejected — opens the broker to anyone with a domain + an OIDC discovery endpoint. The whole point of the allowlist is fail-closed.
- **Subdomain wildcards** (`https://*.auth0.com`) — every Auth0 tenant has the form `<tenant>.auth0.com` ; a wildcard would simplify multi-tenant configuration. Rejected for v0.7.1 because wildcard semantics can be subtly wrong (`https://attacker.auth0.com` would match) — explicit allowlist is safer. Future ADR if a deployment proves the wildcard pattern is needed.

## Verification

Tests in `tests/test_oidc.py` (11 new) :

- `test_multi_issuer_verifier_requires_at_least_one_verifier` — empty list → ValueError
- `test_multi_issuer_verifier_lists_issuers` — issuers attribute populated
- `test_multi_issuer_routes_to_correct_verifier` — token from A → A's path, token from B → B's path
- `test_multi_issuer_rejects_token_with_iss_not_in_allowlist` — iss=attacker → reject
- `test_multi_issuer_rejects_empty_token` — guard
- `test_multi_issuer_rejects_garbage_token` — non-JWT input
- `test_multi_issuer_rejects_token_without_iss` — missing iss claim → reject
- `test_make_verifier_returns_multi_for_comma_separated_env` — env activation
- `test_make_verifier_returns_single_for_one_issuer` — single → bare OIDCVerifier (back-compat)
- `test_make_verifier_strips_trailing_slashes_in_multi_issuer` — normalisation
- `test_make_verifier_blank_issuer_in_csv_dropped` — `a,,b` → 2 issuers

End-to-end (manual, multi-tenant SaaS shape) :

```bash
$ SECURED_CLAUDE_IDP_ISSUER="https://tenant-a.auth0.com,https://tenant-b.auth0.com" \
  SECURED_CLAUDE_OIDC_AUDIENCE=secured-claude \
  SECURED_CLAUDE_MAX_STALE_AGE_S=1800 \
  secured-claude up
$ # Tokens minted by either tenant are accepted ; tokens from a 3rd tenant
$ # (e.g. https://attacker.auth0.com) are rejected with a WARNING log line.
```

## References

- [ADR-0034](0034-principal-provider-abstraction.md) — provider abstraction (per-principal mapping is independent of which IdP minted the token)
- [ADR-0038](0038-jwt-validation-and-oidc-discovery.md) — single-issuer JWT validation (the foundation this wraps)
- [ADR-0039](0039-max-stale-age-for-cache-and-jwks.md) — staleness bound (each issuer's cache is independently bounded)
- [ADR-0040](0040-mtls-client-cert-on-idp-fetches.md) — mTLS (shared across all wrapped verifiers in this rev)
- v0.7+ tickets :
  - Per-issuer audience / bearer / mTLS config (split shared envs into per-issuer JSON config)
  - Background JWKS refresh thread (proactive re-fetch before TTL expiry, per-issuer)
  - Prometheus counter for routing-misses (allowlist-reject events)
  - Subdomain wildcard support (e.g. `https://*.auth0.com`) if a deployment proves the pattern is safer than enumerating tenants

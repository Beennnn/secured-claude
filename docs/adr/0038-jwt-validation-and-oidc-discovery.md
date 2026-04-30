# 38. JWT validation in /check + OIDC discovery

Date: 2026-04-30
Status: Accepted

## Context

[ADR-0034](0034-principal-provider-abstraction.md) shipped the `PrincipalProvider` abstraction (v0.5) so the broker could pull the principal directory from a URL. [ADR-0037](0037-http-principals-cache-and-bearer-auth.md) closed the operational gaps in v0.6.0 (TTL cache + bearer auth + stale-on-error).

The remaining piece for end-to-end OIDC integration is **proving** at request time that a given hook call actually represents the principal it claims to be. Until v0.6.0 the broker trusted the `principal_id` field at face value :

> v0.5 / v0.6.0 — the hook posts `{principal_id: "alice", ...}` to the broker. The broker has no cryptographic evidence that the agent really is `alice` ; it just looks up `alice` in the directory and returns its roles + attributes to Cerbos. An attacker who can write to the agent container's env (e.g. via a compromised entrypoint or leaked .env file) can spoof any principal_id by setting `SECURED_CLAUDE_PRINCIPAL=alice`.

The accepted enterprise pattern is **OIDC + JWT** : the agent is provisioned with a short-lived JWT signed by the IdP, the agent presents the token on every tool call, and the broker validates the signature against the IdP's JWKS before trusting the `sub` claim as the principal_id.

## Decision

### Optional JWT field on `/check` request

`CheckRequest` gains an optional `token: str | None` field. When present AND the broker has a verifier configured (`SECURED_CLAUDE_IDP_ISSUER` env), the token is validated and the `sub` claim becomes the effective `principal_id`. When absent OR no verifier is configured, the `principal_id` field is used as-is (v0.5 / v0.6.0 behaviour, fully back-compat).

```json
POST /check
{
  "tool": "Read",
  "tool_input": {"file_path": "/workspace/foo.py"},
  "principal_id": "claude-code-default",
  "session_id": "s1",
  "token": "<JWT signed by the IdP>"
}
```

### `OIDCVerifier` + on-demand discovery

New module `src/secured_claude/oidc.py` exposes `OIDCVerifier(issuer, audience, jwks_cache_ttl_s, bearer_token, timeout_s)`. The first JWT to hit the broker triggers :

1. `GET <issuer>/.well-known/openid-configuration` → find `jwks_uri`
2. `GET <jwks_uri>` → fetch the JWK set

Both URLs are cached for `jwks_cache_ttl_s` (default 3600 = 1 hour). A JWKS rotation eventually shows up after the TTL expires ; before that, the broker uses the cached set. **Stale-on-error semantics carried over from ADR-0037** : if discovery or JWKS fetch fails AND we have a cached version, the cache is reused (loud log line). If no cache → reject the token (DENY response).

### Validation rules

`OIDCVerifier.verify_token(token)` returns `dict[str, Any]` (claims) on success or `None` on any failure. Successful validation requires :

- Signature matches a JWK in the IdP's JWKS (matched by `kid` header)
- `iss` claim equals the configured issuer (trailing slash stripped)
- `exp` claim not past
- `nbf` claim, if present, not future
- `aud` claim equals the configured audience IF `SECURED_CLAUDE_OIDC_AUDIENCE` is set ; skipped otherwise (default open-aud — operators with a strict aud requirement set the env)

Supported algorithms (in order, first kid match wins) : `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`. **HS\* (HMAC) deliberately rejected** — symmetric keys are inappropriate for IdP-broker integration where the broker doesn't (and shouldn't) hold the signing secret.

### Fail-closed in `/check`

```python
if req.token and oidc_verifier is not None:
    claims = oidc_verifier.verify_token(req.token)
    if claims is None:
        # → DENY immediately, audit row written, Cerbos NOT consulted
    else:
        sub = str(claims.get("sub") or "")
        if not sub:
            # → DENY (missing sub claim)
        else:
            effective_principal_id = sub  # Cerbos called with this id
```

A failed verification short-circuits to `decision=DENY` with `cerbos_reason="JWT validation failed (signature / iss / exp / aud)"` (or `"JWT validation failed : missing 'sub' claim"`). The audit row records the **claimed** `principal_id` (from the request body), not the JWT's failed `sub`, so log analysis can spot principal-impersonation attempts.

### Hook side : forward the agent token

`secured-claude-hook` reads `SECURED_CLAUDE_AGENT_TOKEN` env (empty / unset = no token sent). When set, the hook adds a `token` field to the `/check` POST body. Operators inject the token via :

- Docker secret mount (`/run/secrets/agent-token`) + entrypoint exports the env
- IdP SDK that fetches a token at agent startup and sets the env
- File-based helper that watches a token-rotation hook and re-exports the env

The token format is opaque to the hook ; only the broker validates it.

### Bearer auth on JWKS fetch — reuse v0.6.0 pattern

The JWKS endpoint may itself sit behind auth (rare but possible for internal IdPs that don't expose JWKS publicly). The verifier reuses the same `SECURED_CLAUDE_IDP_BEARER_TOKEN` env from ADR-0037 — both discovery + JWKS requests carry the `Authorization: Bearer <token>` header.

## Why `requests` for JWKS, not PyJWT's `PyJWKClient`

PyJWT's built-in `PyJWKClient` uses `urllib.request.urlopen()` directly. The standard test mock (`responses` library) only intercepts `requests`-based calls. Switching to `responses` + `urllib_mock` to test both paths would have doubled the test fixture surface. We instead :

1. Fetch JWKS via `requests.get()` (ADR-0037-aligned, mockable in tests)
2. Manually find the matching JWK by `kid`
3. Use `jwt.PyJWK(jwk_data).key` to extract the public key
4. Pass the key to `jwt.decode()` for the actual signature verification

Trade-off : we lose PyJWKClient's built-in cache (we replicate it ourselves in `_get_jwks`). Net code is ~30 lines more, but tests don't need to monkeypatch `urllib`.

## Consequences

**Positive** :
- An attacker who controls the agent container's env can no longer spoof `principal_id` — they'd need the IdP's signing key, which the broker validates against the IdP's JWKS.
- Standard OIDC patterns work : Auth0 (M2M tokens), Keycloak (service accounts), GitHub Actions (`id-token: write` permission), GCP Workload Identity, AWS IAM Roles Anywhere.
- 21 new tests cover happy path + 9 reject paths (expired / wrong issuer / wrong audience / unsigned / wrong-key / discovery 5xx / JWKS 5xx / empty token / garbage token / missing sub) + 6 env-resolution paths. Total now 187 tests (was 161 in v0.6.0).
- Backward-compatible : `verifier=None` (the default when `SECURED_CLAUDE_IDP_ISSUER` is unset) keeps the v0.6.0 behaviour. Existing deployments unaffected.

**Negative** :
- New dep `pyjwt[crypto]>=2.10.0` (which pulls `cryptography`). Adds ~6 MB to the wheel + ~12 MB of native libs in the broker container (we don't ship the verifier in the agent container — the agent only forwards the token).
- JWKS rotation latency : up to 1 hour with the default cache TTL. Operators with stricter rotation needs set `SECURED_CLAUDE_OIDC_JWKS_TTL_S=300` (5 min) or lower.
- Permanent IdP misconfig (revoked issuer URL, deleted JWKS endpoint) keeps serving stale JWKS indefinitely. Mitigated by WARNING log per stale serve. v0.7+ ticket : optional `max_stale_age_s` that flips back to reject after N minutes.

**Neutral** :
- The verifier is a single instance per broker process (FastAPI lifespan) ; cache lives in the verifier instance ; restart = cache reset (same as ADR-0037 for principals).
- HS\* algorithm rejection is deliberate — symmetric secrets between agent + broker would be an anti-pattern in this trust topology.

## Alternatives considered

- **Cerbos JWT plugin** — Cerbos PDP can verify JWTs natively if configured. Rejected for v0.6.1 because (a) we'd lose the audit-row-with-jwt-deny-reason pattern (Cerbos returns a generic deny without telling us *why* the JWT was invalid), (b) the broker is the natural place to map `sub` → directory entry → roles+attributes BEFORE asking Cerbos.
- **mTLS for agent ↔ broker** — would replace the JWT hook payload with cert-based auth on the HTTP connection itself. v0.7+ ticket (requires cert provisioning + pinning at broker startup ; bigger op surface than env-injected JWT).
- **Skip OIDC discovery, hardcode `jwks_uri` env** — simpler config but loses the auto-rotation safety. Most IdPs already publish discovery, and the cost is one extra HTTP request the first time the broker starts. Rejected.
- **Sliding TTL on JWKS cache** — bookkeeping for marginal cache-hit rate gain ; same ADR-0037 reasoning, fixed TTL is operationally simpler. Rejected.
- **Verify JWT in the hook (agent-side)** — would push the JWKS-fetch + validation into every hook process. Rejected : the hook should be stateless + fast (sub-50ms p99) ; the verifier needs to cache JWKS across calls, which only the long-lived broker can do efficiently. Plus, hook-side validation means trusting the hook to actually do it — the broker is the trust boundary.

## Verification

Tests in `tests/test_oidc.py` (21 new) :

- `test_verifier_accepts_valid_token` — happy path
- `test_verifier_rejects_expired_token` — exp past
- `test_verifier_rejects_wrong_issuer` — iss mismatch
- `test_verifier_enforces_audience_when_configured` — aud handling matrix
- `test_verifier_rejects_unsigned_token` — alg=none CVE-2015-9235
- `test_verifier_rejects_signed_with_other_key` — kid not in JWKS
- `test_verifier_handles_discovery_5xx_no_cache` — fail-closed without cache
- `test_verifier_handles_jwks_5xx_no_cache` — same on JWKS endpoint
- `test_verifier_returns_none_for_empty_token` — guard
- `test_verifier_sends_bearer_on_discovery_and_jwks` — Authorization header on both fetches
- `test_verifier_caches_jwks_within_ttl` — discovery hit only once on 2nd call
- `test_verifier_discovery_without_jwks_uri_returns_none` — malformed discovery
- `test_verifier_returns_none_for_garbage_token` — non-JWT input
- `test_make_verifier_returns_none_when_issuer_unset` — feature-flag default
- `test_make_verifier_returns_none_when_issuer_blank` — whitespace-only env
- `test_make_verifier_picks_up_issuer_env` — env activation
- `test_make_verifier_picks_up_audience_env` — optional aud
- `test_make_verifier_picks_up_jwks_ttl_env` — TTL override
- `test_make_verifier_invalid_jwks_ttl_falls_back_to_default` — non-numeric env
- `test_make_verifier_picks_up_bearer_token_env` — bearer on JWKS
- `test_make_verifier_strips_trailing_slash_in_issuer` — normalisation

Tests in `tests/test_gateway.py` (5 new) :

- `test_check_with_token_and_no_verifier_keeps_principal_id` — back-compat
- `test_check_with_valid_token_derives_principal_from_sub` — sub override
- `test_check_with_invalid_token_denies_immediately` — fail-closed + audit row
- `test_check_with_token_missing_sub_denies` — missing sub claim
- `test_check_without_token_when_verifier_set_uses_principal_id` — token-optional flow

End-to-end (manual) :

```bash
$ SECURED_CLAUDE_IDP_URL=https://idp.example.com/principals \
  SECURED_CLAUDE_IDP_BEARER_TOKEN=svc-account-token \
  SECURED_CLAUDE_IDP_ISSUER=https://idp.example.com \
  SECURED_CLAUDE_OIDC_AUDIENCE=secured-claude \
  secured-claude up
$ # broker fetches principals (cached 5 min) AND validates JWTs against
$ # https://idp.example.com/.well-known/openid-configuration (cached 1 h).
$ # An agent presenting an expired token gets DENY + audit row visible
$ # via `secured-claude audit --denied --since 1m`.
```

## References

- [ADR-0027](0027-multi-principal-directory.md) — principal directory contract (the data model)
- [ADR-0034](0034-principal-provider-abstraction.md) — provider abstraction
- [ADR-0037](0037-http-principals-cache-and-bearer-auth.md) — cache + bearer pattern reused for JWKS
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JSON Web Token (JWT)
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) — JSON Web Key (JWK) Set
- [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) — `/.well-known/openid-configuration` schema
- v0.7+ tickets :
  - mTLS auth between agent and broker (replace bearer/JWT with cert-based auth)
  - max_stale_age_s for JWKS cache (flip to reject after N minutes of upstream failure)
  - Optional JWT issuer ALLOWLIST (multi-issuer support — accept tokens from any of N IdPs)

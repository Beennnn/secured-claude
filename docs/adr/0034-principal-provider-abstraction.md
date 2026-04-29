# 34. PrincipalProvider abstraction (foundation for OIDC / IdP integration)

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0027](0027-multi-principal-directory.md) introduced `config/principals.yaml` as the per-principal roles + attributes directory. v0.5 backlog : "External IdP integration (Auth0/OIDC dynamic principals)" — the directory should be loadable from an IdP server, not just a static file, so operators with central identity infrastructure (Auth0, Keycloak, Okta, generic OIDC) can manage principals there.

A full IdP integration with JWT validation in `/check`, OIDC discovery, and per-request user lookup is a substantial v0.6+ feature. v0.5 ships the **foundation** : a `PrincipalProvider` abstraction with two concrete implementations (file + URL) so v0.6 can extend with proper OIDC features without a re-architecting cycle.

## Decision

Add `secured_claude/principals.py` with :

- `PrincipalProvider` ABC with one abstract method `load() → dict[principal_id → {roles, attributes}]`.
- `YAMLPrincipalProvider(path)` — the v0.3.1 behaviour.
- `HTTPPrincipalProvider(url, timeout_s)` — fetches principals from a URL. Accepts JSON or YAML body (same `principals:` schema).
- `make_provider()` factory that picks the right provider from env :
  1. `SECURED_CLAUDE_IDP_URL` set + non-empty → HTTP provider.
  2. Otherwise → YAML provider, path from `SECURED_CLAUDE_PRINCIPALS` or `config/principals.yaml`.

Both providers return the same `{principal_id → {roles, attributes}}` shape. The broker's `make_app(principals=None)` calls `make_provider().load()` if no override is supplied — drop-in, no caller-side change.

The original `gateway.load_principals(path=None)` becomes a backward-compat shim around `YAMLPrincipalProvider`. v0.3.1 callers that passed a `Path` keep working.

### Fail-open semantics

Both providers fail-open : on missing file, malformed YAML, HTTP error, invalid response body — return the single-default fallback `{claude-code-default: {roles: [agent, claude_agent], attributes: {trust_level: 0}}}`. Matches the v0.3.1 contract from ADR-0027 and the v0.5 ADR-0033 default. Cerbos still gates every action ; an empty/broken IdP doesn't translate into "everything denied."

The trade-off : if the IdP is supposed to elevate a session to `claude-code-trusted` and the IdP is down, the session falls back to `claude-code-default` (less privileged). That's the right safety direction.

### What's deliberately NOT in v0.5

- **JWT validation** in `/check`. The agent still passes `principal_id` as a string ; the broker still trusts it. v0.6+ ticket : extend the request schema to carry a JWT, broker verifies the signature against the IdP's JWKS endpoint, the `principal_id` is then derived from the JWT `sub` claim.
- **OIDC discovery**. v0.6+ : fetch `<issuer>/.well-known/openid-configuration` to get `jwks_uri`, `userinfo_endpoint`, etc. v0.5 just fetches a static URL.
- **Per-request user lookup**. v0.6+ : if a JWT carries a user ID not in the cached principals, the broker can fetch fresh from the IdP's userinfo endpoint.
- **TTL caching**. v0.5's `HTTPPrincipalProvider.load()` is called once per `make_app()` invocation (gateway startup). The broker doesn't cache between calls. v0.5 ticket : add a TTL-based cache so a cold-startup burst doesn't hammer the IdP.
- **Auth on the provider URL**. v0.5 fetches the URL with no auth headers. If operators put their principals behind an authenticated endpoint, they need to pre-sign the URL or hit it via an authenticated proxy. v0.6+ ticket : `SECURED_CLAUDE_IDP_BEARER_TOKEN` env or mTLS.

These are NOT shipped in v0.5 because :
- The architecture is now in place — v0.6+ can extend `HTTPPrincipalProvider` (or add a sibling) without re-touching the gateway.
- The fail-open semantics + 152 tests give confidence the foundation works.
- Each deferred item deserves its own ADR (JWT validation = security-critical ; cache = performance trade-off ; auth = operator-config tradeoff).

## Consequences

**Positive** :
- v0.5 ticket "External IdP integration" closed at the architectural-foundation scope.
- Operators can now serve `config/principals.yaml` from any HTTP endpoint they control (e.g. a small Lambda that reads from Auth0 + emits the YAML schema).
- 15 new tests cover both providers + the factory's env resolution. Total now 152 tests (was 137).
- The broker's behaviour is unchanged for v0.3.1+v0.4 deployments — the YAML provider remains the default.

**Negative** :
- New module + a new dep tree branch (the `responses` test-only dep was already there ; production-side adds nothing — `requests` was already a dep).
- The fail-open trade-off : a broken IdP silently degrades to default principal. Operators relying on IdP-provided trust elevation should monitor the broker's logs.

**Neutral** :
- `gateway.load_principals` shim preserves backward compat for any external caller. Internal code now uses `make_provider().load()` directly.

## Alternatives considered

- **Skip the abstraction, hardcode HTTP in gateway** — would work for v0.5 but bake the assumption of "static file XOR URL". The provider pattern lets v0.6 add (e.g.) `KubernetesConfigMapPrincipalProvider`, `S3BucketPrincipalProvider`, `AuthZeroAPIPrincipalProvider` as siblings without touching the gateway code. Rejected — the abstraction's marginal cost is one ABC + 4 methods.
- **Full OIDC + JWT in v0.5** — substantial scope (JWKS fetch, JWT verification, per-request user lookup, refresh tokens). Each piece is a security-critical decision. Rejected ; v0.5 is the foundation, v0.6+ is the depth.
- **Use `httpx` instead of `requests`** — `requests` is already in our deps (used by the hook) so no new dep. `httpx` would be marginally faster + async-native, but v0.5's `load()` is sync (called once at startup). Rejected for v0.5 ; revisitable if the broker becomes async end-to-end.

## Verification

Tests in `tests/test_principals.py` (15 new) :

YAML provider (4) :
- valid file → reads correctly + default injected
- missing file → fallback
- malformed YAML → fallback
- mixed file (some invalid entries) → drops bad, keeps good

HTTP provider (5) :
- JSON body → reads correctly
- YAML body → reads correctly (same parser)
- 5xx response → fallback
- unreachable URL → fallback (no `responses.add` for it)
- HTML/garbage body → fallback

`make_provider()` factory (5) :
- no env → YAML provider with default path
- `SECURED_CLAUDE_PRINCIPALS` set → YAML with custom path
- `SECURED_CLAUDE_IDP_URL` set → HTTP provider
- `SECURED_CLAUDE_IDP_TIMEOUT_S` custom → HTTP with custom timeout
- empty `SECURED_CLAUDE_IDP_URL` → falls through to YAML
- invalid timeout string → defaults to 5.0

End-to-end (manual) :

```
$ # Operator runs a tiny Auth0 → JSON shim at port 9001 that emits :
$ # {"principals": {"alice": {"roles": [...], "attributes": {...}}}}
$ SECURED_CLAUDE_IDP_URL=http://localhost:9001/principals \
    secured-claude up
$ # Broker pulls principals from the URL on startup ; alice now has the
$ # roles + attributes the IdP says.
```

## References

- [ADR-0027](0027-multi-principal-directory.md) — principals directory ; this ADR's source-of-truth abstraction
- [ADR-0031](0031-principal-validate-cli.md) — `principal validate` lint CLI (still operates on YAML files only ; v0.6 ticket : add `--url` mode)
- [ADR-0033](0033-broker-containerised-for-ci-smoke.md) — CI smoke ; uses YAML provider in compose env
- v0.6 tickets :
  - JWT validation in `/check` (the broker verifies the agent's token against IdP JWKS)
  - OIDC discovery (`.well-known/openid-configuration` fetch)
  - TTL-based cache for `HTTPPrincipalProvider`
  - Bearer token / mTLS auth on the provider URL

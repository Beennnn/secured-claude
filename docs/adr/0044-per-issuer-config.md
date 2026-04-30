# 44. Per-issuer audience / bearer / mTLS / TTL config

Date: 2026-04-30
Status: Accepted (with scope-honesty addendum below)

## Scope honesty (added 2026-04-30 post-review)

**The "multi-tenant SaaS with mixed-auth modes" framing below is speculative for the project's actual use case.** `secured-claude` is a single-user dev tool ; the realistic deployment has ONE IdP. Per-issuer JSON config solves a problem (mixed-auth across N tenants) that the project doesn't have.

This ADR is a layer-on-top of ADR-0041's already-speculative multi-issuer support : *if* an operator runs N issuers, *and* those issuers need different audience / bearer / mTLS / TTL, the JSON env lets them configure that. Both conditions are out-of-scope of the project's primary use case ; the code is ~30 lines of permissive JSON parser + a factory loop, no operational risk when unused.

What's left as honest framing : the JSON env is the right abstraction *if* per-issuer config is ever needed. Until then it's documented but unused. The shared envs (`SECURED_CLAUDE_OIDC_AUDIENCE`, etc.) cover 100 % of single-issuer + same-config-across-tenants scenarios — i.e. the realistic deployment.

## Context

[ADR-0041](0041-multi-issuer-allowlist.md) shipped multi-issuer ALLOWLIST in v0.7.1 : comma-separated `SECURED_CLAUDE_IDP_ISSUER` activates `MultiIssuerVerifier`. **All wrapped issuers share the same** :

- `SECURED_CLAUDE_OIDC_AUDIENCE` (one global aud)
- `SECURED_CLAUDE_IDP_BEARER_TOKEN` (one global bearer)
- `SECURED_CLAUDE_IDP_CLIENT_CERT_PATH` + `_KEY_PATH` (one global mTLS pair)
- `SECURED_CLAUDE_OIDC_JWKS_TTL_S` (one global JWKS TTL)
- `SECURED_CLAUDE_MAX_STALE_AGE_S` (one global max-stale-age)

That works for simple multi-tenant SaaS where every tenant is configured the same way (e.g. all 3 customer Auth0 tenants accept the same `aud="my-app"`). It breaks for the realistic enterprise case :

- **Per-tenant audience** : tenant A is on Auth0 (audience = the API identifier), tenant B is on Keycloak (audience = the client ID). Different conventions, different values.
- **Per-tenant secrets** : the bearer token / mTLS cert needed to fetch the JWKS is different per tenant — the broker holds N service-account credentials, one per IdP.
- **Per-tenant TTLs** : tenant A is a critical primary IdP (5-min JWKS TTL for fast rotation pickup), tenant B is a backup IdP for DR (1-hour TTL is fine).

ADR-0041 explicitly flagged this as v0.7+ : *"Single shared audience / bearer / mTLS pair config across all issuers. Per-issuer overrides not supported in v0.7.1 — operators with mixed-auth needs (one IdP needs bearer on JWKS, another doesn't) need a future ADR."*

## Decision

New env `SECURED_CLAUDE_IDP_CONFIG` accepts a JSON list. Each entry is a self-contained config block for one issuer :

```bash
SECURED_CLAUDE_IDP_CONFIG='[
  {
    "issuer": "https://tenant-a.auth0.com",
    "audience": "https://api.tenant-a.com",
    "bearer_token": "auth0-mgmt-tok-tenant-a",
    "jwks_cache_ttl_s": 300,
    "max_stale_age_s": 1800
  },
  {
    "issuer": "https://idp.tenant-b.local",
    "audience": "tenant-b-client-id",
    "client_cert_path": "/etc/ssl/tenant-b.crt",
    "client_key_path": "/etc/ssl/tenant-b.key",
    "jwks_cache_ttl_s": 3600
  }
]'
```

### Schema

Each entry is an object with one required field (`issuer`) and seven optional override fields :

| Field | Type | Falls back to |
|---|---|---|
| `issuer` | string | (required) |
| `audience` | string \| null | `SECURED_CLAUDE_OIDC_AUDIENCE` env |
| `bearer_token` | string \| null | `SECURED_CLAUDE_IDP_BEARER_TOKEN` env |
| `client_cert_path` | string \| null | `SECURED_CLAUDE_IDP_CLIENT_CERT_PATH` env |
| `client_key_path` | string \| null | `SECURED_CLAUDE_IDP_CLIENT_KEY_PATH` env |
| `jwks_cache_ttl_s` | float | `SECURED_CLAUDE_OIDC_JWKS_TTL_S` env (default 3600) |
| `max_stale_age_s` | float \| null | `SECURED_CLAUDE_MAX_STALE_AGE_S` env (default None) |
| `timeout_s` | float | `SECURED_CLAUDE_IDP_TIMEOUT_S` env (default 5.0) |

Missing fields fall back to the shared envs — so operators with N similar tenants can set the shared envs once and override only the per-tenant differences :

```bash
# Shared default for all 3 tenants
SECURED_CLAUDE_OIDC_AUDIENCE=my-app
SECURED_CLAUDE_OIDC_JWKS_TTL_S=300

# Per-tenant overrides : just the bearer tokens
SECURED_CLAUDE_IDP_CONFIG='[
  {"issuer": "https://tenant-a.auth0.com", "bearer_token": "tok-a"},
  {"issuer": "https://tenant-b.auth0.com", "bearer_token": "tok-b"},
  {"issuer": "https://tenant-c.auth0.com", "bearer_token": "tok-c"}
]'
```

### Resolution order

`make_verifier()` checks env vars in this order, first match wins :

1. `SECURED_CLAUDE_IDP_CONFIG` (JSON list) → per-issuer overrides apply
2. `SECURED_CLAUDE_IDP_ISSUER` (comma-separated) → shared-env path (v0.7.1)
3. Neither set → return `None` (JWT verification disabled, v0.6.0 behaviour)

When both 1 and 2 are set, the JSON config wins. We log nothing here — operators who set both have an explicit migration in progress, and the resolution is deterministic + documented.

### Single-issuer in JSON form

A 1-element JSON list returns a bare `OIDCVerifier`, not a wrapper :

```bash
SECURED_CLAUDE_IDP_CONFIG='[{"issuer":"https://idp.example.com","audience":"app"}]'
# → OIDCVerifier(issuer="https://idp.example.com", audience="app")
```

This keeps the back-compat shape : code that type-asserts `isinstance(v, OIDCVerifier)` continues to work for single-issuer deployments using either env style.

### Malformed JSON behaviour

The parser is permissive : invalid JSON, non-list root, or empty list all fall through to path 2 (the v0.7.1 env-based resolution). The malformed config logs a `WARNING` so operators see the issue, but the broker doesn't crash on startup. Per-entry malformations (e.g. an entry missing `issuer`) are silently skipped ; a config of `[{"audience":"orphan"}, {"issuer":"https://valid"}]` returns just the valid entry.

Strict validation could land in v0.7.x+ (validate against a JSON schema, reject malformed configs at startup) but for now permissive-with-warnings matches the rest of the broker's fail-open-then-warn posture.

## Consequences

**Positive** :
- Multi-tenant SaaS with mixed auth modes unlock cleanly : tenant on Auth0 with one audience + tenant on Keycloak with another + tenant on a PKI-backed internal IdP with mTLS — all in one broker.
- Compliance-tier flexibility : critical primary IdP gets a tight JWKS TTL + max-stale-age while a backup IdP gets a lenient config.
- 12 new tests cover the JSON parsing + per-issuer overrides + fallback cascade. Total now 253 tests (was 240 in v0.7.3).
- Backward-compatible : existing v0.7.1 deployments using `SECURED_CLAUDE_IDP_ISSUER` are unaffected ; the JSON path is opt-in.

**Negative** :
- JSON in env vars is awkward to escape — operators using `docker run -e` or shell-export need single-quoting around the JSON. Mitigation : operators using docker-compose / k8s use the multi-line YAML literal form.
- The shared envs become both "the only config knob" (v0.7.1 path) AND "fallback defaults" (v0.7.4 path), which is two roles for one set of env names. The ADR documents the dual purpose ; the variable behaviour itself is unchanged when JSON config is unset.
- Adding 8 optional fields per entry creates a wider config surface ; future v0.7.x additions (e.g. cipher pinning) need to land in BOTH the shared env AND the JSON schema. Acceptable cost ; the alternative (separate sub-modules per config concern) would be more elaborate for a single-class verifier.

**Neutral** :
- `MultiIssuerVerifier`'s wrapper pattern (ADR-0041) is unchanged — per-issuer config produces N differently-configured `OIDCVerifier` instances that the wrapper holds.
- The `_parse_idp_config_env()` helper lives in `oidc.py` next to `make_verifier()` ; it didn't warrant a new module.
- Counters + histograms (ADR-0042 + ADR-0043) work unchanged on per-issuer configs — observations are aggregated across all issuers.

## Alternatives considered

- **YAML instead of JSON** — supports comments + multi-line strings, more readable. Rejected because the broker already loads `pyyaml` for the YAML principal directory ; adding YAML to env parsing creates two YAML touchpoints with different schemas. JSON keeps env parsing self-contained.
- **Path-to-config-file env** (`SECURED_CLAUDE_IDP_CONFIG_PATH=/etc/secured-claude/idp.yaml`) — clearer for large configs, but adds filesystem-read complexity (file watching, atomic-write semantics, mode bits). Operators who want file-based config can `cat` it into the env at startup ; the broker doesn't need its own loader.
- **Split per-concern envs** (`SECURED_CLAUDE_IDP_AUDIENCES="a:aud-a,b:aud-b"`) — proliferates env vars, breaks the JSON schema migration pattern Kubernetes operators expect.
- **Per-issuer config from a separate module** (`src/secured_claude/idp_config.py`) — over-engineering for a 30-line parser + factory loop. Inlined into `oidc.py`.
- **Strict validation with JSON Schema** (jsonschema library + a config schema file) — more rigorous but adds a dep + a runtime schema-file. Permissive parsing matches the v0.7.1 fail-open style ; strict validation can land later if operator demand emerges.

## Verification

Tests in `tests/test_oidc.py` (12 new) :

- `test_idp_config_json_with_per_issuer_audience_overrides` — per-issuer aud
- `test_idp_config_json_with_per_issuer_bearer_overrides` — per-issuer bearer
- `test_idp_config_json_with_per_issuer_mtls_overrides` — per-issuer cert/key
- `test_idp_config_json_falls_back_to_shared_env_when_field_missing` — inheritance
- `test_idp_config_single_issuer_returns_bare_verifier` — N=1 → OIDCVerifier (not wrapper)
- `test_idp_config_overrides_idp_issuer_env` — resolution order : JSON wins
- `test_idp_config_invalid_json_falls_back` — malformed JSON → fallback to v0.7.1 path
- `test_idp_config_not_a_list_falls_back` — JSON dict (not list) → fallback
- `test_idp_config_entry_missing_issuer_dropped` — silent per-entry skip
- `test_idp_config_all_entries_invalid_falls_back` — all-bad → fallback
- `test_idp_config_unset_falls_back_to_idp_issuer_env` — default v0.7.1 behaviour
- `test_idp_config_per_issuer_jwks_ttl_override` + `_per_issuer_max_stale_override` — TTL fields

End-to-end (manual, multi-tenant SaaS with mixed-auth) :

```bash
$ SECURED_CLAUDE_IDP_CONFIG='[
    {"issuer":"https://tenant-a.auth0.com","audience":"api-a","bearer_token":"tok-a"},
    {"issuer":"https://tenant-b.keycloak.local","audience":"client-b",
     "client_cert_path":"/etc/ssl/b.crt","client_key_path":"/etc/ssl/b.key"},
    {"issuer":"https://backup.local","jwks_cache_ttl_s":86400}
  ]' \
  secured-claude up
$ # broker accepts JWTs from any of 3 tenants, validates each against
$ # its own JWKS using its own audience + auth method.
```

## References

- [ADR-0034](0034-principal-provider-abstraction.md) — provider abstraction (per-principal mapping is independent of which IdP minted the token)
- [ADR-0037](0037-http-principals-cache-and-bearer-auth.md) — bearer auth (one of the per-issuer overrides)
- [ADR-0038](0038-jwt-validation-and-oidc-discovery.md) — JWT validation (the shape per-issuer config tunes)
- [ADR-0040](0040-mtls-client-cert-on-idp-fetches.md) — mTLS (one of the per-issuer overrides)
- [ADR-0041](0041-multi-issuer-allowlist.md) — multi-issuer ALLOWLIST (this rev's per-issuer config layered on top)
- v0.7+ tickets :
  - Path-to-config-file env (`SECURED_CLAUDE_IDP_CONFIG_PATH`) for large multi-tenant configs
  - JSON Schema validation at startup
  - Hot-reload of per-issuer config without broker restart

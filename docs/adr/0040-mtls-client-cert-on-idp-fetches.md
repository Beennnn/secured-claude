# 40. mTLS client cert/key on IdP fetches (principals + JWKS + discovery)

Date: 2026-04-30
Status: Accepted

## Context

[ADR-0037](0037-http-principals-cache-and-bearer-auth.md) added `bearer_token` to `HTTPPrincipalProvider` so the principals endpoint can sit behind an authenticated wall. [ADR-0038](0038-jwt-validation-and-oidc-discovery.md) reused the same env on JWKS / discovery fetches. The result covers ~80 % of real-world IdP integrations (Auth0 mgmt API, GitHub Actions OIDC token, GCP Workload Identity, internal service-account brokers).

The remaining 20 % needs **mTLS** (mutual TLS — both ends present a client certificate during the TLS handshake). Common cases :

- **Government / military enclaves** : zero-trust deployments where every service-to-service call uses cert-based auth ; bearer tokens are explicitly forbidden because they're long-lived secrets that can be replayed.
- **Internal IdPs behind PKI** : enterprises with their own root CA + automated cert rotation ; mTLS is the auth layer ON TOP of network-level segmentation.
- **HSM-backed keys** : the broker's identity is held in a hardware security module ; the cert is a mTLS leaf signed by the HSM. Replacing this with a bearer token would mean the key leaves the HSM (anti-pattern).

ADR-0037's "v0.7+ mTLS" ticket was deferred specifically because it adds 2 env vars + a `requests cert=` kwarg — small in scope but not on the v0.6.0 critical path. v0.6.2 closed all the higher-priority items (cache + bearer + max-stale-age), so v0.7.0 is the right slot.

## Decision

Both `HTTPPrincipalProvider` and `OIDCVerifier` gain `client_cert_path` + `client_key_path` parameters. When **both** are set, the provider passes the pair as the `cert=` kwarg on every `requests.get()` call (principals fetch / discovery fetch / JWKS fetch). `requests` then uses them to present a client certificate during the TLS handshake.

```python
HTTPPrincipalProvider(
    url,
    client_cert_path="/etc/ssl/client.crt",
    client_key_path="/etc/ssl/client.key",
)
OIDCVerifier(
    issuer="https://idp.internal/",
    client_cert_path="/etc/ssl/client.crt",
    client_key_path="/etc/ssl/client.key",
)
```

Two shared env vars across both factories : `SECURED_CLAUDE_IDP_CLIENT_CERT_PATH` + `SECURED_CLAUDE_IDP_CLIENT_KEY_PATH`. Same shared-env reasoning as ADR-0039 : a deployment that needs mTLS on principals almost always needs the same on JWKS.

### Both halves required

If only one of the env vars is set (e.g. cert path without key path, possible during a rotation if the script writes the key first), `_cert_kwarg()` returns `None` and the request goes through WITHOUT mTLS. Rationale : `requests` requires both halves of the pair ; passing `(cert, None)` would crash the request. Failing silently to "no mTLS" is wrong for security but a hard error here would prevent the broker from booting during rotations. The compromise is :

1. Both halves set → mTLS active.
2. Either half missing → mTLS inactive (the bearer / unauthenticated path takes over).
3. Both halves missing → no mTLS, no log noise (the v0.6.x path).

Operators who require mTLS as a hard precondition set their cert-rotation tooling to write **both files atomically** (rename-into-place) rather than rely on the broker's hard-fail.

### Bearer + mTLS coexistence

Both auth modes are independent : the bearer token (if set) goes in the `Authorization` header AND the cert pair (if set) negotiates the TLS handshake. Some operators use both (mTLS for transport identity + bearer for application-level audit identity). The provider doesn't enforce mutual exclusion.

## Why `requests` `cert=` kwarg, not a custom TLS context

`requests.Session` exposes a `cert=` kwarg that accepts either a string (combined PEM with cert + key) or a tuple `(cert_path, key_path)`. The latter is the standard form for separately-managed cert + key files (the typical `cert-manager` / `vault-issuer` output shape). We pass the tuple form.

Alternatives rejected :
- **Custom `urllib3.PoolManager` with `ssl_context`** : more control (cipher whitelist, OCSP stapling) but substantially more code + breaks `responses` mocking. v0.7+ ticket if a deployment needs cipher pinning.
- **`SSL_CERT_FILE` env var** : sets the *trust* anchor, not the *client* identity. Unrelated to mTLS.

## Consequences

**Positive** :
- Closes the v0.7 mTLS ticket. The broker can now integrate with PKI-backed IdPs in zero-trust environments.
- Combined with bearer auth (ADR-0037) and JWT validation (ADR-0038), the broker covers all 4 standard IdP integration patterns : unauthenticated, bearer-only, mTLS-only, mTLS+bearer.
- 12 new tests cover both modules : both-paths-set / either-missing / partial-env / kwarg-passes-to-requests / env wiring. Total now 216 tests (was 204 in v0.6.2).
- Backward-compatible : default `client_cert_path=client_key_path=None` matches v0.6.2.

**Negative** :
- File-system access at request time : `requests` reads the cert/key files for every call (no caching). For a broker with a 5-min principals cache + 1-hour JWKS cache, this is a few reads per hour ; not a concern. Future optimization could load the cert once into a `urllib3` context.
- Cert rotation requires **both** files updated atomically. A naïve rotation that writes one then the other can produce a brief window where `_cert_kwarg()` returns None. Documented in the ADR's "Both halves required" section.
- No support for cert chains containing intermediates (the `cert=` kwarg expects a leaf cert only). Operators with intermediate-CA chains pass the full chain in the leaf file (PEM concat) — this works because `requests` passes the whole file content to OpenSSL.

**Neutral** :
- The cert/key files are read by the broker process only — never logged, never sent over the wire (only the public cert reaches the IdP, never the private key). This is `requests.get()` standard behaviour.
- mTLS on the agent ↔ broker connection (instead of agent ↔ IdP) is a different ADR — that would need server-side cert config in broker startup. Not in scope for v0.7.0.

## Alternatives considered

- **PEM-bundled file (cert + key in one file)** — `requests cert=` accepts a single string form. We don't expose this because two-file form is the cert-manager / vault-issuer output convention. Operators with bundle files concat-and-write to one of the two paths or rotate to use the bundle form via a future env (rejected for v0.7.0).
- **mTLS on agent ↔ broker** — would replace the JWT in the hook payload with cert-based auth on the broker connection. Different ADR (v0.7+) ; needs server-side cert config + cert-pinning logic on broker startup.
- **Auto-rotate on file change** — watchdog the cert/key files and reload on inotify. Premature complexity for v0.7.0. Operators rotate the broker process when certs rotate (or just rely on `requests` reading the file on every call, which already picks up changes).
- **Hard-fail on partial env** — set cert without key crashes the broker at startup. Rejected for ergonomic reasons (rotation atomicity is the operator's problem ; broker should be resilient during writes-in-progress).

## Verification

Tests in `tests/test_principals.py` (6 new) :

- `test_http_provider_cert_kwarg_set_when_both_paths_provided` — both set → tuple
- `test_http_provider_cert_kwarg_none_when_either_path_missing` — partial → None (3 sub-cases)
- `test_http_provider_passes_cert_kwarg_to_requests` — kwarg forwarded on fetch
- `test_http_provider_no_cert_kwarg_when_unset` — default → None forwarded
- `test_make_provider_picks_up_mtls_env` — env activation
- `test_make_provider_mtls_partial_env_treated_as_unset` — partial env → None

Tests in `tests/test_oidc.py` (6 new) :

- `test_verifier_cert_kwarg_none_when_unset` — default
- `test_verifier_cert_kwarg_set_when_both_paths_provided` — both set
- `test_verifier_cert_kwarg_none_when_partial` — partial
- `test_verifier_passes_cert_kwarg_to_requests` — both discovery + JWKS calls carry cert kwarg
- `test_make_verifier_picks_up_mtls_env` — env activation
- `test_make_verifier_mtls_partial_env_treated_as_unset` — partial env

End-to-end (manual, requires a real PKI) :

```bash
$ SECURED_CLAUDE_IDP_URL=https://idp.internal/principals \
  SECURED_CLAUDE_IDP_ISSUER=https://idp.internal \
  SECURED_CLAUDE_IDP_CLIENT_CERT_PATH=/etc/ssl/broker.crt \
  SECURED_CLAUDE_IDP_CLIENT_KEY_PATH=/etc/ssl/broker.key \
  SECURED_CLAUDE_MAX_STALE_AGE_S=1800 \
  secured-claude up
$ # broker presents mTLS leaf on every principals + discovery + JWKS fetch ;
$ # IdP validates the cert against its trust anchor + maps the SAN to a
$ # service-account identity ; broker still validates JWT signatures per ADR-0038.
```

## References

- [ADR-0037](0037-http-principals-cache-and-bearer-auth.md) — bearer auth (the other ~80 % of cases)
- [ADR-0038](0038-jwt-validation-and-oidc-discovery.md) — JWT validation (mTLS doesn't replace this)
- [ADR-0039](0039-max-stale-age-for-cache-and-jwks.md) — max-stale-age (the shared-env pattern reused here)
- [requests cert= docs](https://requests.readthedocs.io/en/latest/user/advanced/#client-side-certificates)
- v0.7+ tickets :
  - mTLS for agent ↔ broker (replace JWT with cert-based auth on the hook connection)
  - Multi-issuer ALLOWLIST (accept tokens from N IdPs)
  - Background JWKS refresh thread (proactive re-fetch before TTL expiry)
  - Per-provider stale-age envs (split shared SECURED_CLAUDE_MAX_STALE_AGE_S into 2)
  - Prometheus counter for mTLS / bearer / cache-drop events
  - Cipher pinning via custom `urllib3` context (rare ; only if a deployment needs FIPS 140-2 mode etc.)

# 42. Prometheus counters + /metrics endpoint

Date: 2026-04-30
Status: Accepted

## Context

The v0.6 → v0.7.1 wave (ADR-0037 through ADR-0041) added five new failure modes that all emit a WARNING log line :

- Principals cache dropped past max_stale_age (ADR-0039)
- JWKS cache dropped past max_stale_age (ADR-0039)
- Multi-issuer routing miss : iss not in allowlist (ADR-0041)
- mTLS partial-env (cert without key) silently treated as unconfigured (ADR-0040)
- JWT-deny in `/check` : signature / iss / exp / aud / kid violation (ADR-0038)

Operators who want to alert on these need to **scrape the broker logs**, parse the WARNING lines, classify them, and feed counts into a metrics backend. Three problems with that :

1. **Log format is not a contract.** A future commit that polishes a log line breaks the alert.
2. **Cardinality is unbounded.** Log lines include URLs, ages, principal IDs ; alert engines that turn each unique line into a series risk running out of cardinality budget.
3. **Per-event counts via log scraping are slow.** A 5-second alert window needs sub-second log ingestion ; Prometheus scrape is the standard 15-second pattern.

Prometheus counters give us a stable contract, fixed cardinality (only enum labels, no high-cardinality fields), and the standard 15-second scrape pattern. Operators can build Grafana dashboards on the rates without touching the log pipeline.

## Decision

Add 9 counter families exposed at `GET /metrics` in the Prometheus text exposition format (the same content type as every Prometheus exporter on the web). Counters live in a new module `src/secured_claude/metrics.py` ; providers + verifiers + gateway import them and `.inc()` on the relevant events.

### Counter inventory

```text
secured_claude_principals_fetch_total{outcome="success|error"}
secured_claude_principals_cache_hit_total
secured_claude_principals_stale_served_total
secured_claude_principals_stale_dropped_total
secured_claude_principals_fallback_total
secured_claude_jwt_verify_total{outcome="accepted|rejected_signature|rejected_iss|rejected_exp|rejected_aud|rejected_other"}
secured_claude_jwks_fetch_total{outcome="success|error"}
secured_claude_jwks_stale_dropped_total
secured_claude_multi_issuer_routing_total{outcome="routed|rejected_iss_not_in_allowlist|rejected_no_iss"}
secured_claude_check_decisions_total{decision="ALLOW|DENY|jwt_deny|cerbos_unavailable"}
```

Cardinality budget : every label is a fixed enum from a closed set. The maximum number of time-series per broker is bounded by the sum of the label combinations (~25 series per broker process). Safe at any deployment size.

### Dedicated registry

Counters use a dedicated `prometheus_client.CollectorRegistry` (not the default global one) so :

- Tests can spin up isolated registries without leaking counter state.
- Other libraries that auto-register to the default registry (httpx, requests, etc. — none currently, but defensive) don't appear in our `/metrics` output.

Operators who want to scrape Python runtime metrics (GC, fork, CPU) deploy a separate `prometheus_client.start_http_server()` ; out of scope for v0.7.2.

### `/metrics` endpoint

Trust boundary same as `/check` : the broker binds to `127.0.0.1:8765` so only host-local processes can scrape. No auth on the endpoint — the loopback bind IS the auth boundary, matching the `/check` and `/health` pattern. Operators wanting remote scraping put a reverse proxy in front (nginx + IP allowlist + mTLS, etc.) ; out of scope for the broker itself.

The endpoint is a standard FastAPI route in `gateway.make_app()` ; no separate HTTP server.

### Counter increment placement

Counters increment at the point of decision :

- **In the providers** : after the HTTP outcome is known (success / error), inside the cache-hit / stale-serve / fallback branches.
- **In the verifier** : in each `except` branch of `jwt.decode()` (one per error type) AND on the success path.
- **In the multi-issuer wrapper** : at the routing decision point (allowlist hit / miss / no-iss).
- **In the gateway** : on every `/check` decision (ALLOW / DENY / jwt_deny / cerbos_unavailable).

Why per-error-type labels on `jwt_verify_total` : the operator's alert is "what KIND of JWT-deny is happening ?" — a sudden spike in `rejected_iss` likely means a misconfigured allowlist ; a spike in `rejected_signature` likely means JWKS rotation lag or active impersonation attempts ; a spike in `rejected_exp` likely means clock drift. Different alert thresholds + different runbooks per cause.

## Consequences

**Positive** :
- Operators can alert on every documented failure mode without log scraping. Standard Prometheus + Grafana stack.
- 5 alerts covered by these counters that previously required log-pipeline access :
  - `rate(jwt_verify_total{outcome=~"rejected_.*"}[5m]) > 1` — JWT-deny spike
  - `rate(jwks_fetch_total{outcome="error"}[5m]) > 0.1` — JWKS upstream degraded
  - `principals_stale_dropped_total > 0` — IdP misconfig escalating
  - `rate(multi_issuer_routing_total{outcome=~"rejected_.*"}[5m]) > 1` — impersonation attempts
  - `rate(check_decisions_total{decision="cerbos_unavailable"}[5m]) > 0.1` — Cerbos PDP degraded
- 10 new tests verify the counter wiring (endpoint exposes all families + each event increments the right label). Total now 237 tests (was 227 in v0.7.1).
- Backward-compatible : no behaviour change ; only metrics emission added.

**Negative** :
- New dep `prometheus-client>=0.21` (~50 KB pure Python, no native code). Adds to broker container image but minimal footprint.
- `/metrics` endpoint exposes which features are active (zero-valued counters appear if the corresponding code path is wired). An attacker who can hit the broker's loopback can enumerate the broker's auth modes via `/metrics`. Mitigated by trust boundary (broker is loopback-only ; if an attacker is on loopback they already won).
- Counter increment adds ~1 µs per `/check` call. Hook latency budget (50 ms p99) is unaffected.

**Neutral** :
- Counter values reset on broker restart (Prometheus standard). Operators store the rate, not the absolute count.
- The dedicated registry means we don't auto-collect Python runtime metrics ; out of scope for the broker (which is a security gateway, not a Python runtime monitor).
- Tests share the global registry across runs — counter values accumulate across test cases. The test pattern reads `before` and asserts `after == before + 1` to be order-independent.

## Alternatives considered

- **OpenTelemetry metrics + OTLP push** — more flexible (push to Grafana Cloud, Datadog, Honeycomb, etc.) but adds 3-4 deps + an OTLP collector. Prometheus scrape is the lowest-common-denominator and Grafana Cloud / VictoriaMetrics / Mimir all speak it natively. v0.7.x can add OTel later if a deployment proves the need.
- **Histograms instead of counters** — would let operators see latency distributions for `/check` and JWT verify. Useful but not the primary v0.7.2 ask ; counters cover the alerting surface, histograms can come in v0.7.3+ if needed.
- **`/metrics` on a separate port** — operationally cleaner (different RBAC for scrape vs. agent traffic) but doubles the broker's listening surface. Same loopback bind = same trust boundary, simpler operationally.
- **No labels on `jwt_verify_total`** — single counter for "any JWT-deny" would have less cardinality but would lose the per-cause runbook differentiation. Cardinality stays bounded (6 enum values max), and the ops value of "what KIND of failure" is high.

## Verification

Tests in `tests/test_metrics.py` (10 new) :

- `test_metrics_endpoint_serves_prometheus_text` — endpoint returns 200 with prometheus content-type + all 5 counter families visible
- `test_check_decision_counter_increments_on_allow` — ALLOW path
- `test_check_decision_counter_increments_on_deny` — DENY path
- `test_check_decision_counter_increments_on_cerbos_failure` — cerbos_unavailable path
- `test_check_decision_counter_increments_on_jwt_deny` — jwt_deny path
- `test_principals_fetch_counter_increments_on_success` — fetch success
- `test_principals_fetch_counter_increments_on_error` — 503 path
- `test_principals_cache_hit_counter_increments` — within-TTL cache hit
- `test_metrics_render_returns_bytes` — render() shape
- `test_metrics_content_type_is_prometheus_format` — content-type header

End-to-end (manual) :

```bash
$ secured-claude up
$ curl -s http://127.0.0.1:8765/metrics | head -20
# HELP secured_claude_check_decisions_total Cerbos /check decisions...
# TYPE secured_claude_check_decisions_total counter
secured_claude_check_decisions_total{decision="ALLOW"} 0.0
...
$ # Hit /check a few times, re-curl /metrics, watch counters increment.
```

Operator runbook excerpt (Grafana alert YAML — example for an operator's pipeline) :

```yaml
- alert: SecuredClaudeJWTDenySpike
  expr: rate(secured_claude_jwt_verify_total{outcome=~"rejected_.*"}[5m]) > 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "JWT-deny rate elevated — possible IdP rotation lag or impersonation"
    runbook: "Check broker logs for 'OIDC : JWT validation failed'. If
              rejected_signature spike, check JWKS rotation. If rejected_exp,
              check clock sync."
```

## References

- [ADR-0001](0001-cerbos-as-policy-decision-point.md) — Cerbos PDP (the decision counters reflect)
- [ADR-0009](0009-hook-fails-closed.md) — fail-closed (the cerbos_unavailable counter signals)
- [ADR-0037](0037-http-principals-cache-and-bearer-auth.md) — TTL cache (cache_hit / fetch counters)
- [ADR-0038](0038-jwt-validation-and-oidc-discovery.md) — JWT validation (jwt_verify counter)
- [ADR-0039](0039-max-stale-age-for-cache-and-jwks.md) — max-stale-age (stale_dropped counters)
- [ADR-0040](0040-mtls-client-cert-on-idp-fetches.md) — mTLS (no counter ; partial-env case is rare + log-only)
- [ADR-0041](0041-multi-issuer-allowlist.md) — multi-issuer (routing counter)
- [Prometheus client docs](https://github.com/prometheus/client_python) — exposition format + Counter API
- v0.7+ tickets :
  - Histograms for `/check` latency + JWKS fetch latency (when latency-distribution alerting demand emerges)
  - OTLP push exporter alongside Prometheus pull (when a deployment needs vendor-neutral metrics)
  - Background JWKS refresh thread (proactive re-fetch before TTL expiry)

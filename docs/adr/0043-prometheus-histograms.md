# 43. Prometheus histograms for latency distributions

Date: 2026-04-30
Status: Accepted (with scope-honesty addendum below)

## Scope honesty (added 2026-04-30 post-review)

**This ADR was originally written with multi-burn-rate-SLO framing, which is a misfit for the project's actual use case.** `secured-claude` is a single-user dev tool : one developer on their laptop, a loopback HTTP broker, ~tens of `/check` calls per minute at most. There is no operator team, no Grafana dashboard, no on-call rotation.

The histograms themselves are still useful for **diagnostics** — `curl /metrics | grep duration_seconds` answers "is the broker slow ?" when a developer is troubleshooting. ADR-0002's 50 ms p99 latency reference is an aspirational target (a hook that hangs annoys Claude Code), not a contractual SLO with burn-rate alerts.

The "Decision" section below keeps the implementation as-shipped (4 histogram families with custom-tuned buckets — no harm in having them) but the surrounding "operator alerts on SLO breach" framing is **speculative for a personal-proxy deployment**. Operators running `secured-claude` in a centralised broker pattern (cluster of agents pointing at a shared broker — out-of-scope of the v0.1 design but possible to deploy) might use the histograms for SLO tracking ; everyone else uses them for ad-hoc latency debugging.

## Context

[ADR-0042](0042-prometheus-metrics.md) added 9 counter families covering every documented failure mode. Counters answer "is something failing ?" but not "is something *slow* ?". The histograms below answer the second question.

- **Latency reference** : ADR-0002 cites 50 ms p99 as the round-trip target — a hook that takes longer than a perceptible blink interrupts the developer's flow with Claude Code. A diagnostic ratio of "how often does my broker exceed 50 ms ?" is useful to detect a slow IdP / Cerbos / audit-DB without log digging.
- **JWKS fetch is the slowest path** : on cache miss, the broker hits the IdP over HTTP. ~100–500 ms typical for a healthy IdP ; substantially worse points at the IdP-side or network layer.
- **Per-stage attribution** : when `/check` is slow, *which* stage caused it ? Histograms per-stage tell that story.

## Decision

Add 4 histogram families to the existing metrics module, observed at the corresponding decision point :

```text
secured_claude_check_duration_seconds            # gateway /check end-to-end
secured_claude_jwt_verify_duration_seconds       # OIDCVerifier.verify_token()
secured_claude_jwks_fetch_duration_seconds       # JWKS HTTP fetch (miss only)
secured_claude_principals_fetch_duration_seconds # principals HTTP fetch (miss only)
```

### Bucket tuning

Two bucket schemes :

**Broker latency** (`/check` + JWT verify) — sub-50 ms typical :

```python
(0.001, 0.002, 0.005, 0.010, 0.020, 0.050,
 0.100, 0.250, 0.500, 1.0, 2.5, 5.0)
```

12 buckets covering 1 ms through 5 s. Tight at the bottom (1/2/5/10/20/50 ms) for the in-budget regime, then escalating coarsely for tail outliers. Operators alert on the 50 ms boundary (p99 above that = SLO violation).

**Fetch latency** (JWKS + principals) — ~100–500 ms typical, HTTP roundtrip :

```python
(0.010, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0)
```

9 buckets covering 10 ms through 10 s. Wider at the bottom because sub-10ms is unreachable (HTTP roundtrip alone is 5+ ms even on localhost) ; the meaningful gradient starts at 50 ms.

### Why custom buckets, not Prometheus defaults

Prometheus's default histogram buckets are `(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0)` — 14 buckets evenly distributed on a log scale. That wastes cardinality at the high end (we don't care about 7.5s vs 10s — both mean "broken") and is too coarse at the bottom (5 ms vs 10 ms is the difference between fast and slow for `/check`).

Per-broker custom buckets give us 12-bucket density in the operating range with no wasted slots.

### Cardinality budget

Each histogram with N buckets produces N+2 time-series (one per bucket, plus `_count` and `_sum`). 4 histograms × ~12 buckets = ~56 series added. Combined with v0.7.2's ~25 counter series, the broker now exposes ~80 series total. Bounded ; safe at any deployment size.

### Observation placement

- `CHECK_DURATION_SECONDS` : context-managed around the entire `/check` body (JWT verify → Cerbos → audit insert) so the histogram captures the full hook→broker→hook latency that the agent actually sees.
- `JWT_VERIFY_DURATION_SECONDS` : context-managed around `OIDCVerifier.verify_token()` so we can attribute /check latency to JWT verify vs Cerbos.
- `JWKS_FETCH_DURATION_SECONDS` : context-managed around the cache-miss `requests.get(jwks_uri)` call. Cache hits skip the HTTP and don't observe (otherwise the histogram would be dominated by ~0 ms hits and the actual fetch latency would be invisible).
- `PRINCIPALS_FETCH_DURATION_SECONDS` : same pattern for principals fetches.

A `with metrics.X.time():` block records the wall-clock duration when it exits (success OR exception), so failed fetches contribute to the histogram too — operators see *slow failures* same as slow successes.

## Consequences

**Positive** :
- Diagnostic visibility : `curl /metrics | grep duration_seconds` answers "is the broker slow ?" when troubleshooting. No log digging.
- Per-stage attribution : when `/check` is slow, the JWT/JWKS/principals histograms isolate the cause.
- Slow-failure visibility : a `RequestException` caught in the JWKS fetch still observes its duration (the `with .time():` block fires on exit even on exception).
- For the rare deployment running the broker in a centralised pattern (cluster of agents → shared broker), operators CAN build the standard `histogram_quantile()` SLO dashboards. Out-of-scope of v0.1 design but the data is there.
- 3 new tests verify the histogram families are exposed + observations record per call. Total now 240 tests (was 237 in v0.7.2).
- Backward-compatible : pure additive, no behaviour change.

**Negative** :
- ~56 new time-series at /metrics — the cardinality budget is bounded but not free. Operators with very tight cardinality budgets can configure Prometheus to drop the `_bucket` series and keep only `_count` + `_sum` (loses quantile capability ; keeps avg latency).
- Per-stage histograms create double-counting in summed views : a `/check` call that takes 10 ms total (JWT 2 ms + Cerbos 7 ms + audit 1 ms) shows 10 ms in CHECK_DURATION + 2 ms in JWT_VERIFY. That's fine for per-stage attribution but operators graphing "total broker time" should pick exactly one histogram, not sum across.
- Histogram observation has a small but non-zero CPU cost (~1 µs per observation). At /check rates of < 1 kHz the impact is invisible.

**Neutral** :
- Histograms reset on broker restart same as counters. Operators store the rates over moving windows, not the absolute distributions.
- Tests share the global registry, so observation counts accumulate across tests within a session. The test pattern checks "the rendered output changed" rather than "_sum increased by exactly N" to be order-independent.

## Alternatives considered

- **Prometheus default buckets** — simpler but wastes cardinality at the wrong end of the range. Rejected.
- **Native histograms** (Prometheus 2.40+ feature) — exponentially-spaced buckets auto-tuned by the server. Promising but the prometheus-client library doesn't yet emit them in the text exposition format that the broker's `/metrics` uses. Future ADR if the protocol stabilises.
- **Summaries instead of histograms** — quantiles computed client-side. Cheaper to compute (no buckets), but quantiles can't be aggregated across instances. Histograms allow `histogram_quantile()` over the federation. Rejected.
- **Single histogram with per-stage label** — e.g. `secured_claude_duration_seconds{stage="check|jwt_verify|jwks_fetch|principals_fetch"}`. Keeps the metric count low but couples the stages' bucket schemes (one of broker-tight or fetch-wide ; can't have both). Rejected ; per-stage histograms with their own tuned buckets is cleaner.
- **Manual `time.monotonic()` deltas** — same effect, more boilerplate. The `with metric.time():` context manager is the official prometheus-client idiom.

## Verification

Tests in `tests/test_metrics.py` (3 new) :

- `test_check_duration_histogram_observes_per_check_call` — `/check` POST → histogram count + sum increment
- `test_metrics_endpoint_exposes_histogram_families` — all 4 histogram families visible at /metrics
- `test_principals_fetch_duration_observed_on_fetch` — successful principals fetch records observation

End-to-end (manual) :

```bash
$ secured-claude up
$ for i in $(seq 1 100); do
    curl -s -X POST http://127.0.0.1:8765/check \
      -H "content-type: application/json" \
      -d '{"tool":"Read","tool_input":{"file_path":"/workspace/foo.py"}}'
  done > /dev/null
$ curl -s http://127.0.0.1:8765/metrics | grep "check_duration_seconds_bucket"
secured_claude_check_duration_seconds_bucket{le="0.001"} 0.0
secured_claude_check_duration_seconds_bucket{le="0.002"} 12.0
secured_claude_check_duration_seconds_bucket{le="0.005"} 87.0
secured_claude_check_duration_seconds_bucket{le="0.01"} 98.0
secured_claude_check_duration_seconds_bucket{le="0.02"} 100.0
...
$ # Diagnostic : if check_duration_seconds_count grows but the bucket
$ # distribution shifts toward the high end, broker is getting slow.
```

(The original draft of this ADR included a Grafana alert recipe with multi-burn-rate semantics. Removed in the post-review scope-honesty pass — multi-burn-rate alerting is a SaaS gateway pattern, not a personal-proxy pattern. The data is there for anyone who wants it ; the doctrine is documented in the Google SRE workbook for those who need it.)

## References

- [ADR-0002](0002-pretooluse-hook-as-interception-point.md) — 50 ms p99 hook latency *target* (aspirational, not a contractual SLO)
- [ADR-0042](0042-prometheus-metrics.md) — counter families this extends with histograms
- [Prometheus histogram_quantile docs](https://prometheus.io/docs/prometheus/latest/querying/functions/#histogram_quantile)
- v0.7+ tickets :
  - Per-issuer histogram labels (when operators need tenant-level latency breakdowns)
  - Native histograms (Prometheus 2.40+) — when prometheus-client adds emission support
  - OTLP push exporter (when a deployment needs vendor-neutral metrics push instead of Prometheus pull)

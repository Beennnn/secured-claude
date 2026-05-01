# 45. Non-features explicitly rejected for the project's scope

Date: 2026-05-01
Status: Accepted

## Context

The v0.6 → v0.7.4 wave shipped 8 versions of progressively-more-enterprise framing on what is fundamentally a **single-user dev tool**. After a user pushback on 2026-04-30 ("you are putting SLO stuff in there when it's just a proxy"), the project added :

- A **scope-honesty addendum** to ADR-0040 / 0041 / 0043 / 0044 admitting the original framing was speculative.
- A **`Scope discipline` section** in the project-level [`CLAUDE.md`](../../CLAUDE.md) with a (1)/(2)/(3) decision rule for future autonomous-loop drift : *who specifically asked for this ?* / *what's the value for the actual single-user use case ?* / *what's the cost ?*
- A [`TASKS.md`](../../TASKS.md) backlog where 3 candidate features were left as 🤔 to-consider.

Subsequent autonomous-loop iterations passed the same 3 candidate features through the (1)/(2)/(3) rule and concluded none of them clear the bar. Rather than letting them sit indefinitely as 🤔 dormant items, this ADR formalises the rejection so future sessions don't re-litigate the question.

## Decision

The following three features are **explicitly out of scope** for the project's primary use case and will not be implemented unless a real user with a named deployment pattern asks for them :

### Non-feature #1 : Agent ↔ broker mTLS (formerly tracked as v0.8)

**Threat it would close** : a malicious local process on the dev's laptop POSTs `/check` to the broker pretending to be the agent.

**Why we are NOT shipping it** : the trust boundary on a single-user dev laptop **is the user**. A malicious process running as the same user already has read access to :
- The agent container's environment variables (including `SECURED_CLAUDE_AGENT_TOKEN` if v0.6.1 JWT is used)
- The audit DB (`~/.local/share/secured-claude/approvals.db` mode 0600)
- The dev's source code, git credentials, browser cookies, etc.

A connection-level cert pinning would not change the realistic threat picture — anything the agent can reach, a same-user malicious process can also reach. mTLS would only help in a multi-user host where different users run different agents, which is **not this project's deployment shape**.

**Cost we'd incur** : ~150-200 lines (uvicorn TLS config, hook cert presentation, cert/key generation at `secured-claude up`, docker-compose volumes, CI smoke with self-signed certs, tests). Plus the ongoing maintenance of cert rotation logic, TLS-version pinning, and cipher suite review.

**If this changes** : a real user with a multi-user shared-host deployment (e.g. CI runner pool with multiple agents, dev-cluster-with-shared-broker pattern) asks for it. Reopen this ADR + write the implementation ADR. Until then, **keep the broker on plain HTTP loopback ; the loopback bind is the trust boundary**.

### Non-feature #2 : Background JWKS refresh thread (formerly tracked as v0.7.5)

**What it would do** : a background thread proactively re-fetches the IdP's JWKS just before the cache TTL expires, so the next `/check` doesn't pay the cache-miss latency.

**Why we are NOT shipping it** : single-user latency tail is **1 fetch per cache TTL window** (default 1 hour). The cache-miss latency hit is a one-time ~100-500 ms event per hour. Per [ADR-0043](0043-prometheus-histograms.md)'s honesty pass, we don't actually have an SLO that this latency would breach — it's a perceptible blink, not an outage.

For the use case where this latency would matter (high-throughput multi-tenant SaaS gateway with tight p99 SLOs), the broker isn't the right architecture in the first place — that deployment would want a CDN-fronted JWKS endpoint with edge caching, not a background thread inside a Python broker.

**Cost we'd incur** : threading lifecycle in FastAPI's `lifespan` context manager, race conditions between foreground reads and background writes to the JWKS cache dict, observability overhead to detect thread death, test infra for time-based scheduling.

**If this changes** : the histograms from [ADR-0043](0043-prometheus-histograms.md) start showing a real latency tail in `secured_claude_jwks_fetch_duration_seconds_bucket{le="0.5"}` that operators flag as user-visible. Reopen with measured data, not speculation.

### Non-feature #3 : OTLP push exporter for metrics

**What it would do** : push metrics via OTLP to Datadog / Honeycomb / Grafana Cloud OTel collectors, instead of the Prometheus pull endpoint at `/metrics`.

**Why we are NOT shipping it** : the realistic single-user-dev-tool deployment doesn't have a metrics backend at all — the operator runs `curl /metrics` for ad-hoc diagnostics ([ADR-0042](0042-prometheus-metrics.md), redressed in the scope-honesty pass). Shipping an OTLP exporter would mean :
- A new transitive dep (`opentelemetry-exporter-otlp` + its grpcio dep, ~30 MB)
- Configuration surface (endpoint URL, auth, TLS cert for the OTel collector)
- Failure-mode debugging when the exporter can't reach the backend (queue limits, retry semantics)

All of that for **zero value** in the primary use case.

**If this changes** : an operator running the broker in a multi-tenant SaaS pattern with vendor-locked metrics infra (Datadog Agent only, no Prometheus pull allowed) asks for it. Even then, the right answer is probably an external Prometheus-to-OTLP relay process, not in-broker OTLP code.

## Consequences

**Positive** :
- Future autonomous-loop sessions read this ADR + the (1)/(2)/(3) rule in [`CLAUDE.md`](../../CLAUDE.md) and skip these candidates without re-litigating.
- The scope of the project becomes explicit : we ship security gating for **a single dev's laptop usage of Claude Code**, not enterprise-grade SaaS infrastructure.
- The 🤔 to-consider items in `TASKS.md` get drained, leaving an empty backlog (per CLAUDE.md TASKS.md convention, the file gets deleted when truly empty — this ADR's existence makes it deletable).

**Negative** :
- A real user with one of these deployment patterns has to argue past this ADR + reopen it. That's the right level of friction — speculative work is the failure mode this ADR exists to prevent.

**Neutral** :
- The existing v0.7.x code (mTLS on IdP fetches, multi-issuer ALLOWLIST, per-issuer config, Prometheus counters/histograms) stays in place. They're documented with scope-honesty addenda. None of them is faulty — they're just over-spec'd for the primary use case ; deleting them now would be churn-for-churn's-sake.

## Alternatives considered

- **Just leave the items as 🤔 in TASKS.md indefinitely.** Rejected — TASKS.md is meant to be drainable ; permanent 🤔 entries become noise.
- **Implement them anyway "for completeness".** Rejected — that's the exact failure mode the scope-honesty pass exists to prevent. "Completeness" is a vanity metric for a personal dev tool.
- **Delete the existing v0.7.x code.** Rejected — the code isn't faulty, just over-spec'd in the docs. Deleting it would force a v0.8.0 breaking release on operators who happen to use the extension points.

## References

- [`CLAUDE.md` § Scope discipline](../../CLAUDE.md) — the (1)/(2)/(3) decision rule this ADR formalises a rejection under.
- [ADR-0040](0040-mtls-client-cert-on-idp-fetches.md) — mTLS on IdP fetches (different from agent↔broker mTLS ; the IdP-fetch mTLS shipped, the agent↔broker mTLS rejected here).
- [ADR-0041](0041-multi-issuer-allowlist.md), [ADR-0043](0043-prometheus-histograms.md), [ADR-0044](0044-per-issuer-config.md) — the other v0.7.x ADRs that carry scope-honesty addenda from the same review pass.
- `TASKS.md` (now empty / deleted post-this-ADR) — the backlog where these 3 items were tracked as 🤔 dormant.

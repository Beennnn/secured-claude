# TASKS

Pending work for the next session. Stripped to items still open or worth considering after the v0.7.4 + scope-honesty pass.

## 🤔 To consider (decide before starting)

The v0.7.x trajectory shipped 8 versions of progressively-more-enterprise framing for what is fundamentally a personal dev tool. The user pushback on 2026-04-30 led to a "scope honesty" addendum on ADR-0040 / 0041 / 0043 / 0044. Before picking up any of these, decide whether they fit the project's actual use case (single-user laptop, loopback broker, ~tens of /check per minute) :

- 🤔 **v0.8 — agent ↔ broker mTLS** — replace JWT-in-payload with cert-based auth on the broker connection itself. ~150-200 lines + tests + ADR. **Real value for personal proxy** : closes "another local process spoofs the agent identity" gap. **Cost** : startup cert config, uvicorn TLS, hook cert-presentation, docker-compose volumes.
- 🤔 **v0.7.5 — background JWKS refresh thread** — proactive re-fetch before TTL expiry. **Real value for personal proxy** : near-zero (single-user latency tail is 1 fetch every hour, not cumulative). **Cost** : threading lifecycle in FastAPI lifespan. Likely YAGNI ; could /schedule a 6-month follow-up if histograms ever show latency tail issues.
- 🤔 **OTLP push exporter** — vendor-neutral metrics push (Datadog / Honeycomb / Grafana Cloud OTel). **Real value for personal proxy** : zero. Out of scope unless someone asks.

## ☐ Open work

(none — the 4 items originally listed here on 2026-04-30 were drained on 2026-05-01 across commits c157ca4, 31ffc37, 40a6b25, 1840596 : README honesty pass, CLAUDE.md scope-discipline section, 9 new red-team scenarios, `policy template` subcommand.)

## 🚫 Blocked

(none)

---

When all items here are done or explicitly cancelled, delete this file + commit the deletion (per CLAUDE.md convention). Don't keep an empty or "nothing pending" stub.

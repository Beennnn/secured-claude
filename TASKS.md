# TASKS

Pending work for the next session. Per CLAUDE.md TASKS convention :
short, scannable, every line is something the next session must act on.

## ☐ Open work

- ☐ **CI smoke + v0.8.1 host-side broker port-8765 conflict** — discovered 2026-05-01 when the v0.8.1 release pipeline `smoke:full-stack` job failed on the macbook-local runner with `bind: address already in use` on `127.0.0.1:8765`. Root cause : v0.8.1 made `secured-claude up` auto-start a HOST-side broker on 8765 (per ADR-0006 trust boundary), but `docker-compose.ci.yml` still has a containerized `secured-claude-broker` service that publishes `127.0.0.1:8765:8765`. On macbook-local (= host runner), the two brokers compete for the same host port. Worked around by stopping the local broker + retrying — but a future user running `secured-claude up` while CI runs will hit the same trap. Fix : either (a) remove the containerized broker from docker-compose.ci.yml and have the CI smoke launch the host-side broker via `secured-claude up` (consistent with ADR-0006), or (b) move the CI broker to a different port (8766) and document the port-isolation contract. Option (a) preferred — single architecture path for prod + CI.
- ☐ **`claude -p` hangs inside the agent container** — discovered during the v0.8.0 smoke (2026-05-01). `claude -p "say hello"` produces no output and no `/check` hook fires, even with `CLAUDE_CODE_OAUTH_TOKEN` set. Investigation showed the L2/L3 confinement is NOT the cause : `*.anthropic.com` is already in the tinyproxy + dnsmasq allowlist, `console.anthropic.com` resolves + returns 302 reachably from inside the container. Likely real causes : (a) OAuth token re-use rejection — the same token the host's Claude Code session uses can't be re-used for a concurrent session inside the agent container ; (b) `claude --print` non-interactive mode in containerized contexts has a known startup issue ; (c) claude waits for an interactive prompt that never arrives via `docker exec`. Fix : (1) reproduce with a fresh OAuth token reserved for the agent only, (2) trace claude's startup with `CLAUDE_DEBUG=1` or strace, (3) document in `docs/dev/agent-container-debug.md`. Until then, the broker-side stack is fully validated end-to-end (291 tests + curl-driven smoke), but interactive sessions through Claude Code itself are blocked on this separate auth issue.

## 🚫 Blocked

(none)

---

Decisions live in ADRs, not here :
- **3 v0.7.x speculative items** (agent↔broker mTLS, background JWKS refresh, OTLP push) → **rejected**, see [ADR-0045](docs/adr/0045-non-features-rejected-for-scope.md).
- **On-the-fly secret redaction** → **shipped** in v0.8.0, see [ADR-0046](docs/adr/0046-on-the-fly-secret-redaction.md).

When all ☐ items here are done, delete this file + commit the deletion (per CLAUDE.md convention).

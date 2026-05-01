# TASKS

Pending work for the next session. Per CLAUDE.md TASKS convention :
short, scannable, every line is something the next session must act on.

## ☐ Open work

- ☐ **CI smoke + v0.8.1 host-side broker port-8765 conflict** — discovered 2026-05-01 when the v0.8.1 release pipeline `smoke:full-stack` job failed on the macbook-local runner with `bind: address already in use` on `127.0.0.1:8765`. Root cause : v0.8.1 made `secured-claude up` auto-start a HOST-side broker on 8765 (per ADR-0006 trust boundary), but `docker-compose.ci.yml` still has a containerized `secured-claude-broker` service that publishes `127.0.0.1:8765:8765`. On macbook-local (= host runner), the two brokers compete for the same host port. Worked around by stopping the local broker + retrying — but a future user running `secured-claude up` while CI runs will hit the same trap. Fix : either (a) remove the containerized broker from docker-compose.ci.yml and have the CI smoke launch the host-side broker via `secured-claude up` (consistent with ADR-0006), or (b) move the CI broker to a different port (8766) and document the port-isolation contract. Option (a) preferred — single architecture path for prod + CI.
- ☐ **`secured-claude audit --since N` filter bug** — discovered 2026-05-01 during the Item #2 verification : `audit --since 2m` returned 0 rows when an ALLOW row was inserted < 1 min earlier ; `--since 1h` returned older rows but missed the most recent. Direct SQLite query confirmed the row was present. Likely a clock/timezone bug in the `--since` parser. Low priority — does not affect security posture, only audit ergonomics.

## 🚫 Blocked

(none)

---

Decisions live in ADRs, not here :
- **3 v0.7.x speculative items** (agent↔broker mTLS, background JWKS refresh, OTLP push) → **rejected**, see [ADR-0045](docs/adr/0045-non-features-rejected-for-scope.md).
- **On-the-fly secret redaction** → **shipped** in v0.8.0, see [ADR-0046](docs/adr/0046-on-the-fly-secret-redaction.md).

When all ☐ items here are done, delete this file + commit the deletion (per CLAUDE.md convention).

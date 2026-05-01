# Changelog

All notable changes are listed here. Each entry mirrors the corresponding
**annotated git tag** — the tag carries the long-form audit (verified test
matrix, mastery axes, regression-vs-prev, known limitations). Read this
file for the orientation, click through to the tag for the proof.

Format inspired by [Keep a Changelog](https://keepachangelog.com/) ;
versions follow [Semantic Versioning](https://semver.org/) — though we
allow patch-bumps to carry behaviour changes that close DX gaps without
affecting the security contract (per CLAUDE.md global "tag every green
stability checkpoint").

To see the full annotation of any tag :

```bash
git show <tag>                       # full annotation + diff
git tag -l <tag> --format='%(contents)'   # annotation only
```

GitLab tag pages : `https://gitlab.com/benoit.besson/secured-claude/-/tags/<tag>`.

---

## [v0.8.3] — 2026-05-01

3 ergonomic/quality fixes batched ; **TASKS.md cleared (zero open ☐)**.

- `fix(audit)` — `--since` accepts relative durations (`5m`, `1h`, `1d`, `1w`) ; ISO 8601 still supported ; clear error message on bad input. New `audit.parse_since()` helper + 9 new tests.
- `fix(tests)` — `cli.cmd_status` tests no longer flake when a developer happens to have `secured-claude up` running. `orchestrator.broker_status` now mocked alongside `orchestrator.status`.
- `fix(ci)` — `docker-compose.ci.yml` no longer publishes a host port for the broker. Was colliding with the v0.8.1 host-side broker on macbook-local. Inline comment documents the omission.

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.8.3)

## [v0.8.2] — 2026-05-01

`claude -p` works end-to-end inside the agent container.

- `fix(agent)` — adds `/home/agent` as 8 MB tmpfs (`uid=1001`) to `docker-compose.yml`. Without it, Claude Code couldn't write `/home/agent/.claude.json` (HOME root file, not inside `.claude/`) → EROFS → 30 s remote-settings timeout → silent exit. Investigation methodology + trace evidence captured in [`docs/dev/agent-container-debug.md`](docs/dev/agent-container-debug.md).
- Closed **TASKS Item #2** (`claude -p` hangs). Hypothesis "OAuth token re-use rejection" disproven by trace.
- End-to-end stack verified live : `claude -p` → PreToolUse hook → broker `POST /check` → Cerbos ALLOW → audit row inserted in SQLite.

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.8.2)

## [v0.8.1] — 2026-05-01

Broker auto-start on `secured-claude up` (DX polish on v0.8.0).

- `feat(orchestrator)` — `secured-claude up` now forks the host-side broker as a background process + writes its PID to `${data_dir}/broker.pid`. `down` stops it. `status` displays it alongside containers in a single table. Closed **TASKS Item #1**.
- New `start_broker()` / `stop_broker()` / `broker_status()` API in `orchestrator.py`. 12 new tests.
- The DX gap from the v0.8.0 smoke is closed : a fresh user gets a working setup with one command (was : had to launch `uvicorn` manually).

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.8.1)

## [v0.8.0] — 2026-05-01

On-the-fly secret redaction (ADR-0046) — closes the content-level exfil vector.

- `feat(security)` — when Claude reads a file via the `Read` tool, the broker now scans the result for 15 curated gitleaks-style patterns (AWS keys, GitHub PAT, GitLab PAT, Slack tokens, Stripe keys, Anthropic, OpenAI, JWT, PEM private keys, DB conn strings, generic api_key) and replaces them with placeholders BEFORE the result reaches the LLM.
- New `redaction.py` module + `hook_post.py` (PostToolUse hook) + `/transform` route on the broker.
- 33 redaction tests with runtime-assembled fixtures (so literal secrets never appear in source — passes GitHub Push Protection).

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.8.0)

## [v0.7.4] — 2026-04-30

Per-issuer JSON config (ADR-0044) — multi-tenant SaaS with mixed-auth modes unlocks.

`SECURED_CLAUDE_IDP_CONFIG` JSON list lets each issuer have its own
audience / bearer / mTLS / TTL.

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.7.4)

## [v0.7.3] — 2026-04-30

Prometheus histograms for latency SLOs (ADR-0043).

4 histogram families (check + jwt_verify + jwks_fetch + principals_fetch)
with custom-tuned buckets matching the 50 ms p99 hook budget. Cardinality
bounded ~80 series total.

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.7.3)

## [v0.7.2] — 2026-04-30

Prometheus counters + `/metrics` (ADR-0042) + 3 CI infra fixes for
re-tag idempotency.

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.7.2)

## [v0.7.1] — 2026-04-30

Multi-issuer ALLOWLIST via `MultiIssuerVerifier` (ADR-0041).

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.7.1)

## [v0.7.0] — 2026-04-30

mTLS client cert/key on IdP fetches (ADR-0040).

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.7.0)

## [v0.6.2] — 2026-04-30

`max_stale_age_s` caps stale-on-error window (ADR-0039).

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.6.2)

## [v0.6.1] — 2026-04-30

JWT validation in `/check` + OIDC discovery (ADR-0038).

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.6.1)

## [v0.6.0] — 2026-04-30

TTL cache + bearer auth on `HTTPPrincipalProvider` (ADR-0037).

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.6.0)

## [v0.5.5] — 2026-04-30

Bake Cerbos policies (close v0.5.4 regression).

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.5.5)

## [v0.5.0..v0.5.4] — 2026-04-29 / 2026-04-30

Smoke-test infrastructure landing : broker CI image + smoke:full-stack
job + sidecar config baked into images (eliminating CI bind-mount
limitations under Docker-in-Docker). Five-item backlog cleared in
v0.5.0.

[v0.5.4](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.5.4) ·
[v0.5.3](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.5.3) ·
[v0.5.2](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.5.2) ·
[v0.5.1](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.5.1) ·
[v0.5.0](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.5.0)

## [v0.4.0] — 2026-04-29

Multi-arch + external hash anchor + real-LLM smoke.

[GitLab tag](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.4.0)

## [v0.3.0..v0.3.1] — 2026-04-29

Four reviewer critiques addressed (intent/confinement, verify-from-outside,
tamper-evident audit log, read-only sidecars). v0.3.1 closes deferred items
(cosign sidecars + runtime smoke + multi-principal).

[v0.3.1](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.3.1) ·
[v0.3.0](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.3.0)

## [v0.2.0..v0.2.1] — 2026-04-29

L2 (tinyproxy) + L3-DNS (dnsmasq) enforcement, hatch-vcs versioning,
deterministic amd64. v0.2.1 pins `@anthropic-ai/claude-code` (closes
the `@latest` supply-chain hole).

[v0.2.1](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.2.1) ·
[v0.2.0](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.2.0)

## [v0.1.0..v0.1.8] — 2026-04-29

First fully-validated release artifact chain. Initial release (v0.1.0)
through closing the publish chain (cosign auth + idempotent twine in
v0.1.4) and the release chain (release-cli + retry-resilient sbom +
grype install in v0.1.5..v0.1.8).

[v0.1.8](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.1.8) ·
[v0.1.7](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.1.7) ·
[v0.1.6](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.1.6) ·
[v0.1.5](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.1.5) ·
[v0.1.4](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.1.4) ·
[v0.1.3](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.1.3) ·
[v0.1.2](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.1.2) ·
[v0.1.1](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.1.1) ·
[v0.1.0](https://gitlab.com/benoit.besson/secured-claude/-/tags/v0.1.0)

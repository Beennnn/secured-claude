# 26. Runtime smoke as a CI gate (no API key burn)

Date: 2026-04-29
Status: Accepted

## Context

The CI pipeline tests :

- **Unit** (117 tests in `tests/`) — Python logic, hash chain, audit log, gateway routing.
- **Audit-demo** (26 red-team scenarios) — Cerbos PDP enforces L1 policies as designed.
- **bin/test-egress.sh** (4 assertions) — L2 + L3 sidecars enforce CONNECT + DNS allowlist.
- **Static security** (bandit, pip-audit, trivy, grype, gitleaks) — no CVEs / secrets in source.

What's missing : **does the freshly-built agent image actually boot ?** The unit tests run against mocked Docker calls. The audit-demo runs Cerbos in a standalone container. The egress test boots only the sidecars. None of these load the agent image and verify its contents.

The v0.1.1 "first end-to-end smoke" caught 5 bugs invisible to all of the above (hook shebang missing, OOMKill, claude wizard exit on no-TTY, etc.). v0.2 + v0.3 documented "runtime smoke recipe runs locally pre-tag but is NOT a CI job — exit ticket : v0.3 with test API key in protected GitLab CI variable" as an unmet promise.

The naive approach would burn Anthropic API budget on every CI run :

```bash
docker compose up -d
secured-claude exec "say hello"   # actual LLM call → costs $0.01-$0.10 per run
```

That's untenable for the project's free-tier CI budget — a few dozen pipelines per day would run dollars of API charges.

## Decision

Run a **wiring-only** runtime smoke that proves the freshly-built images boot correctly **without making any Anthropic API call**. New CI job `test:runtime-smoke` in the `test` stage, gated on `$CI_COMMIT_TAG` or `$CI_COMMIT_BRANCH == main`.

The job pulls the 3 just-built images by `${CI_COMMIT_SHA}` (same bytes `build:image:*` pushed) and verifies :

1. **Agent image — claude binary on PATH** : `docker run ... which claude && claude --version`. Catches a corrupt npm install.
2. **Agent image — hook script wired** : `test -x /usr/local/bin/secured-claude-hook` + `head -1 ... | grep '^#!/usr/bin/env python3'`. Re-runs the v0.1.1 shebang lesson on every release.
3. **Agent image — settings template present** : `test -f /etc/secured-claude/settings.template.json`. Catches a missed COPY in the Dockerfile.
4. **dns-filter image — dnsmasq binary runs** : `dnsmasq --version`. Catches a broken alpine pin.
5. **egress-proxy image — tinyproxy binary runs** : `tinyproxy -v`. Same.

No LLM call. No API key. No cost.

A *real* end-to-end smoke (with API key, on demand) is a separate manual-trigger job tracked for v0.4. The argument for deferring : a real smoke costs both budget and a test API key that has to be kept current ; the wiring smoke catches 90% of the bugs at 0% of the cost.

## Consequences

**Positive** :
- The "v0.3 deferred ticket : runtime smoke as CI gate" is closed (with the wiring-only scope).
- Every release tag pipeline now proves the 3 images boot cleanly. v0.1.1's hook-shebang regression class can't recur silently.
- The job runs on the macbook-local runner via the mounted docker.sock — no DinD, no extra runner, no quota burn.
- Build time : ~30 s (3 image pulls + 5 short `docker run` invocations).

**Negative** :
- Still doesn't catch bugs that only manifest during an actual LLM call (e.g. a prompt injection that bypasses Cerbos, a Claude Code release that ignores `HTTPS_PROXY`). Those need v0.4's manual-triggered real-smoke job.
- The job depends on the registry being reachable from the runner. Network outage = job fails. Acceptable ; same dependency as build:image.

**Neutral** :
- Job runs on tag and main only — not on every dev pipeline. Saves ~30 s on dev iterations.

## Alternatives considered

- **Skip entirely (v0.2 status quo)** — what reviewers flagged as insufficient. Rejected.
- **Real smoke with API key in protected GitLab variable** — works but burns budget and requires key rotation hygiene. Tracked for v0.4 as a manual-trigger job.
- **Simulate Anthropic API with a local mock server** — possible (we'd run mitmproxy or aiohttp returning canned responses) but adds infra and the mock can drift from the real API. Rejected for v0.3.1 ; revisitable if the wiring smoke proves insufficient.
- **Combine into existing test:py313 job** — pollutes the unit-test surface with infrastructure concerns. Rejected ; separate job = clearer failure mode.

## Verification

After v0.3.1 tag pipeline goes green :

```
$ glab ci get -p <pipeline-id> | grep runtime-smoke
test:runtime-smoke:	success
```

Local reproduction (any tag pipeline that's still in the registry retention window) :

```
docker pull registry.gitlab.com/benoit.besson/secured-claude/claude-code:v0.3.1
docker run --rm --entrypoint sh ... -c 'which claude && head -1 /usr/local/bin/secured-claude-hook'
```

## References

- [v0.1.1 runtime-smoke lessons](../dev/developer-environment.md) — the 5 bugs invisible to static gates that motivated this ADR
- [ADR-0017](0017-security-testing-evidence-pipeline.md) — security testing pipeline (this ADR's complement at the wiring layer)
- v0.4 ticket : real-LLM smoke as manual-triggered job with protected `ANTHROPIC_API_KEY_SMOKE` GitLab variable

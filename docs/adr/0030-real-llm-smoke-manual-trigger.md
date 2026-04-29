# 30. Real-LLM smoke as a manual-trigger CI job

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0026](0026-runtime-smoke-ci-gate.md) added a wiring smoke (`smoke:runtime`) that proves the just-built images boot correctly **without burning Anthropic API budget**. It catches v0.1.1's hook-shebang regression class. But it explicitly defers the *real* end-to-end validation :

> "What's missing : does Claude Code's binary actually make a successful API call from inside the secured container ? The wiring smoke proves nothing about reachability of api.anthropic.com, the L2 proxy actually allowing the CONNECT, the API key working, etc."

A real-LLM smoke would catch :
- Anthropic API contract changes (response format, auth header, etc.)
- Network egress regressions (e.g. tinyproxy filter accidentally blocking a sub-domain Claude uses)
- DNS allowlist regressions (e.g. dnsmasq config typo)
- Agent image runtime regressions (e.g. node version incompat with Claude Code)

But running it on every pipeline burns ~$0.01 per call → dollars per day at our pipeline cadence → untenable for a free-tier OSS project.

## Decision

Add `smoke:llm-real` as a **manual-trigger** CI job that exists on every tag pipeline but only runs when an operator clicks it. The operator must first set `ANTHROPIC_API_KEY_SMOKE` as a protected, masked GitLab CI variable.

### Job design (v0.4 scope)

```yaml
smoke:llm-real:
  stage: smoke
  rules:
    - if: $CI_COMMIT_TAG
      when: manual            # ← never auto-run
      allow_failure: true     # ← never block the tag pipeline
  needs:
    - build:image
    - job: build:image:manifest
      optional: true
  script:
    - if [ -z "$ANTHROPIC_API_KEY_SMOKE" ]; then ... helpful error ... ; exit 1 ; fi
    - docker pull "${REG}/claude-code:${SHA}"
    - docker run --rm -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY_SMOKE" \
        "${REG}/claude-code:${SHA}" \
        claude -p "Respond with exactly one word: pong"
    - grep -qi "pong" <<<"$OUTPUT"
```

### Scope deliberately narrow

The v0.4 job runs `claude -p "..."` against the **agent image alone**, NOT the full compose stack. It proves :

- The image boots end-to-end with a real API key.
- The Anthropic API is reachable from inside the container.
- Claude Code's binary handshake + token auth works.
- The model returns a response that contains the expected token.

It does **not** prove :

- The Cerbos PDP gate (audit-demo already covers that).
- The L2 egress proxy + L3 DNS allowlist (bin/test-egress.sh covers that).
- The hook → broker → audit log path (full-stack ; needs the broker running, deferred to v0.4.1).

A full-stack smoke (cerbos + sidecars + broker + agent + actual tool call gated by Cerbos) is the v0.4.1 ticket. It needs the broker containerised (currently host-side per ADR-0006) which is a non-trivial architectural change that deserves its own ADR.

### Operator setup

Before the manual button works, the operator does once :

1. Generate an Anthropic API key with **smoke-run-only** budget cap (e.g. $1/month, separate from production keys).
2. GitLab → Settings → CI/CD → Variables → Add Variable :
   - **Key** : `ANTHROPIC_API_KEY_SMOKE`
   - **Value** : the key from step 1
   - **Protect** : ✓ (only available on protected refs / tags — protects against MR-pipeline exfiltration)
   - **Mask** : ✓ (redacted from job logs)
3. Push a tag → tag pipeline includes `smoke:llm-real` as a manual button → click to run.

The job's first step explicitly checks for the variable and emits a helpful error if missing. No silent failure ; no accidental run without the variable set.

### `allow_failure: true`

This is per CLAUDE.md's "no `allow_failure: true` as a permanent shield" rule's narrow exception : **manual jobs that exist for operator convenience and don't gate releases**. The job is informational : if the operator manually triggers it and Anthropic's API is broken, that's data-of-interest but it shouldn't retroactively fail the release whose tag pipeline already passed.

If we ever flip it to `auto-run on tag` (would require resolving the budget question), `allow_failure: true` would have to go too — and the failure would be a legitimate release blocker.

## Consequences

**Positive** :
- The "real-LLM smoke as CI gate" v0.3 ticket is closed at the manual-trigger scope.
- Operators can sanity-check a release end-to-end with one click + a few cents.
- Job exists, ready to run ; a future v0.4.1 / v0.5 can extend the scope (full stack, autoscale to every tag, etc.) without re-introducing the question.
- The protected variable pattern means the API key stays out of MR pipelines (where the agent itself runs) — no exfiltration path.

**Negative** :
- The job is INFORMATIONAL ONLY. A failed manual smoke doesn't auto-rollback the release. Operator must notice + react.
- Each smoke run costs Anthropic budget. Operators must self-rate-limit.
- Running ONLY on tag pipelines means dev / MR pipelines don't get the real-API safety net. That's intentional ; v0.4.1 may add a weekly cron-triggered smoke against `main` if budget allows.

**Neutral** :
- No code change to the broker / hook / agent image. Pure CI addition.
- The job uses the agent image's existing `claude` binary ; no new test harness.

## Alternatives considered

- **Auto-run on every tag** — burns budget on every release (~$0.01 × N tags / month). Reasonable for a paid project but not for our v0.4 scope. Tracked as v0.5 ticket if budget settles.
- **Mock Anthropic API server** — a local mitmproxy / aiohttp returning canned responses. Doesn't prove reachability of the REAL API. Useful as a v0.4.1 complement (mocks the LLM, runs the full stack including Cerbos/sidecars/broker) but doesn't replace the real-LLM check.
- **Run on a schedule (daily / weekly)** — same budget question scaled down. Tracked as v0.5 if operators want a rolling sanity check.
- **Skip and document as ongoing limitation** — the v0.3.1 status quo. Closed in v0.4.

## Verification

The job's existence is verified by `glab ci lint`. Manual triggering by the operator validates the runtime path :

```
$ glab ci trigger-job <pipeline> smoke:llm-real
Job triggered.
$ glab job trace <job-id>
[...] Claude said: pong
✓ real-LLM smoke green — agent reached api.anthropic.com end-to-end
```

A failure mode (API key revoked, Anthropic API down, image regressed) :

```
[...] FATAL: ANTHROPIC_API_KEY_SMOKE protected variable is not set.
```

OR

```
[...] claude: error: 401 Unauthorized
```

In either case, the operator sees the failure and can investigate. The release pipeline itself is unaffected (`allow_failure: true`).

## References

- [ADR-0006](0006-host-side-broker.md) — broker is host-side ; v0.4 smoke can't reach it from CI without containerising the broker (v0.4.1 ticket)
- [ADR-0026](0026-runtime-smoke-ci-gate.md) — wiring smoke (this ADR's no-budget complement)
- v0.4.1 ticket : containerise the broker so a full-stack smoke can run in CI
- v0.5 ticket : auto-run on tag (if budget settles) + remove `allow_failure: true`

# 33. Broker containerised for CI full-stack smoke

Date: 2026-04-29
Status: Accepted (amends [ADR-0006](0006-host-side-broker.md) for CI use)

## Context

[ADR-0006](0006-host-side-broker.md) keeps the broker host-side : the trust boundary between the LLM-controlled agent and the policy-decision logic must be "container ↔ host", not "container ↔ container". A compromised agent can't escalate to the broker because the broker is on a different namespace + filesystem + capability set.

But the v0.4 ADR-0030 real-LLM smoke could only test the agent's API reachability — not the full stack (agent → hook → broker → Cerbos → audit log). Without a containerised broker reachable from CI, the full-stack smoke needed a host-side process which CI runners don't reliably provide. v0.4.1 ticket : containerise the broker so a true end-to-end CI smoke is possible.

## Decision

Ship a **`Dockerfile.broker`** + **`docker-compose.ci.yml` override** so the broker can run as a 5th container **for CI smoke tests only**. The default `docker-compose.yml` does NOT include the broker — production deployments still run it host-side per ADR-0006.

### `Dockerfile.broker`

`FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim` (digest-pinned per ADR-0008). The build :

1. Adds `wget` for the healthcheck (~250 KB).
2. Sets `SETUPTOOLS_SCM_PRETEND_VERSION_FOR_SECURED_CLAUDE` from a build arg (hatch-vcs needs git history that isn't in the container ; build-arg substitutes for the runtime detection).
3. `uv sync --frozen --no-dev` populates `.venv/` once at build time.
4. Copies `policies/`, `config/`, `cerbos/` for runtime read access.
5. Runs as `broker` user (uid 1001 — same as the agent, parity with ADR-0005).
6. `ENV PATH="/app/.venv/bin:${PATH}"` lets `uvicorn` resolve directly without `uv run` (which would try to re-sync at runtime + fail under read_only:true).
7. ENTRYPOINT runs `uvicorn secured_claude.gateway:make_app --factory --host 0.0.0.0 --port 8765`.

### `docker-compose.ci.yml`

Additive overlay on the default compose. Adds the `broker` service at static IP `172.30.42.6` on the `secured-claude-net` /29 subnet ; overrides the `claude-code` service's `SECURED_CLAUDE_BROKER` env to point at the broker container (`http://172.30.42.6:8765`) instead of the host.

Hardening matches the agent + sidecars :
- `read_only: true`
- `user: "1001:1001"`
- `cap_drop: [ALL]`
- `no-new-privileges`
- `mem_limit: 256m`
- tmpfs for `/tmp` + `/home/broker/.local` (audit DB writes there)

### `bin/test-full-stack.sh`

End-to-end smoke that boots the 5-container stack and POSTs `/check` against the broker for both an ALLOW path (`/workspace/foo.py` read) and a DENY path (`/etc/passwd` read). 2/2 assertions PASS proves :
- Broker container builds + boots
- Cerbos container reachable from broker container at `172.30.42.2:3592`
- L1 policy gate works end-to-end (the agent is NOT in this smoke ; we exercise the broker directly)
- audit DB writes succeed (the `/check` returns a `decision_id`)

### What this DOESN'T change

- Production deployments run the broker host-side per ADR-0006. The `docker-compose.yml` default doesn't reference the broker container.
- The trust-boundary argument from ADR-0006 still holds for production : a compromised agent shouldn't be able to escalate to the broker. In CI, the agent is not part of the smoke (we test the broker directly), so the trust-boundary concern doesn't apply.
- The host-side broker entrypoint is unchanged (operators still run `python -m uvicorn secured_claude.gateway:make_app --factory ...` host-side).

## Consequences

**Positive** :
- v0.4.1 deferred ticket "containerise the broker so smoke:llm-real can do FULL-stack" is closed.
- `bin/test-full-stack.sh` is a new local + CI verification step. v0.5 ships it ; v0.5.1+ may wire it into a `smoke:full-stack` CI job parallel to `smoke:runtime`.
- The CI override pattern is reusable for any future "production runs host-side, CI runs containerised" component.

**Negative** :
- Two docker-compose files to maintain ; operators reading the repo see both and may wonder which one applies. Mitigated by clear comments at the top of each.
- The broker image is ~150 MB (uv + python + .venv with FastAPI/uvicorn/cerbos-client deps). Compared to the agent image (~600 MB) it's small ; in CI we pull from registry once + reuse.

**Neutral — discovered while writing this ADR** :
- Cerbos's `parentRoles` semantics require the derived role to be **explicitly listed in the principal's roles** for activation, not auto-derived from the parent. The `claude-code-default` principal in `config/principals.yaml` was updated from `roles: [agent]` to `roles: [agent, claude_agent]` so the `claude_agent`-gated rules in `policies/filesystem.yaml` activate. This is consistent with what the v0.1 audit-demo always did (hardcoded `principal_roles=["agent", "claude_agent"]`) ; v0.3.1's principal directory dropped the `claude_agent` by mistake when it factored the lookup. Now corrected.

## Alternatives considered

- **Mock broker server** for CI smoke — works but doesn't test the real broker code. Rejected ; we want to detect broker regressions.
- **Make broker container the production default** — would invert ADR-0006's trust-boundary argument. Rejected ; production keeps host-side, CI uses container as a test convenience.
- **Skip the full-stack smoke and document as deferred** — what v0.4 did. Closed in v0.5.

## Verification

```
$ docker compose -f docker-compose.yml -f docker-compose.ci.yml up -d broker
$ bash bin/test-full-stack.sh
===== boot full stack (cerbos + sidecars + broker + agent) =====
===== wait for broker /health =====
  ✓ broker healthy after 2s

===== L1 (Cerbos PDP via broker) — file ALLOW =====
  ✓ ALLOW Read /workspace/foo.py

===== L1 (Cerbos PDP via broker) — file DENY =====
  ✓ DENY Read /etc/passwd

===== verdict =====
  ✓ full-stack enforced end-to-end (2/2 assertions PASS)
```

## References

- [ADR-0006](0006-host-side-broker.md) — host-side broker for production (this ADR amends for CI use only)
- [ADR-0027](0027-multi-principal-directory.md) — principals directory ; updated `claude-code-default` to include `claude_agent` explicitly
- [ADR-0030](0030-real-llm-smoke-manual-trigger.md) — real-LLM smoke (this ADR's CI peer ; full-stack smoke is the next step beyond agent-only)
- v0.5.1 ticket : `smoke:full-stack` CI job that runs `bin/test-full-stack.sh` as part of the tag pipeline
- v0.5.1 ticket : `build:image:broker` Kaniko CI job + cosign-sign + multi-arch

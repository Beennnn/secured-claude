# ADR-0001: Cerbos as the Policy Decision Point

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

secured-claude exists to gate every Claude Code tool call (Read, Write, Edit, Bash, WebFetch, MCP, Task) against a security policy. We need a **Policy Decision Point (PDP)** : a component that, given `(principal, resource, action, attributes)`, returns `ALLOW` or `DENY` with a reason.

Constraints :

- **Policy must be readable by non-developers** — the security team in an enterprise should be able to read, review, and amend policies without learning Python.
- **Policy must be lintable + testable** as artifacts on their own.
- **Policy must be signable** for supply-chain assurance.
- **Decisions must be auditable** — every check leaves a trace.
- **Latency must be low** — we sit on the critical path of every tool call (target p99 < 50 ms total round-trip).
- **Battle-tested** — not a prototype we maintain alone.
- **Vocabulary alignment** — security teams should recognize the tool ; novel YAML schemas raise red flags in vendor reviews.

## Decision

We use [Cerbos](https://cerbos.dev) as the PDP.

- Run as a sidecar Docker container (`cerbos/cerbos:0.42.0` pinned by digest, see [ADR-0008](0008-pin-upstream-images-and-deps.md)) listening on `127.0.0.1:3592` HTTP API.
- Policies live in `policies/*.yaml`, mounted **read-only** into the Cerbos container.
- The host-side broker (Python, see [ADR-0006](0006-host-side-broker.md)) calls Cerbos `/api/check/resources` for every tool intent.
- Policy types used : Resource Policies (per resource type : `file`, `command`, `url`, `mcp_tool`) + Derived Roles (for principal categorization) + Schema validation (optional, planned for v0.2).

## Consequences

### Positive

- **Policy-as-code is the foundation of auditability** : security can `git log policies/`, diff between versions, sign bundles.
- **Cerbos compiles policies** (`cerbos compile policies/`) — syntax errors caught in CI, unreachable rules flagged, dead policies surfaced.
- **Conditional rules are expressive** : Cerbos uses CEL (Common Expression Language). We can write `path.matches('^/workspace/.*') && !path.matches('.git/hooks/')` cleanly.
- **CNCF Sandbox project** — security teams trust CNCF lineage ; pitching is easier ("Cerbos, like the one CNCF blesses") than ("a YAML allowlist we wrote").
- **Decoupling** — if the tool palette changes (Anthropic adds a new built-in tool), we add a Resource Policy without changing broker code.
- **Signed policy bundles** (Cerbos feature) coming v0.2 — policies signed by security team, refused if signature invalid.

### Negative

- **Operational complexity** — adds a container to the deployment ; one more thing to keep updated. Mitigated by Renovate auto-bumps + small image (~30 MB).
- **Latency** — adds one HTTP round-trip per tool call. Cerbos itself decides in < 5 ms typically ; localhost network adds another 1-3 ms. Total budget : ~10 ms p50, < 50 ms p99 measured. Acceptable for an interactive CLI.
- **Learning curve** — contributors must learn Cerbos policy syntax. Mitigated : we ship example policies in `policies/`, the Cerbos docs are good, and CEL is small.

### Neutral

- We adopt the Cerbos resource model (resources have a `kind`, `id`, `attr` map). Maps cleanly to Claude Code's tool model.

## Alternatives considered

- **Hand-rolled YAML allowlist parsed in Python** — simpler, but loses : `cerbos compile`, signed bundles, CEL conditions, security-team familiarity, shared vocabulary. Building those takes us into "let me write my own policy engine" territory, which is the path to bugs.
- **Open Policy Agent (OPA)** — also CNCF, also good. Rejected because :
  - Rego (OPA's language) is harder to teach than Cerbos's CEL-based YAML.
  - OPA is broader-spectrum (general-purpose policy) ; Cerbos is purpose-built for application authorization, which fits us tighter.
  - Cerbos has an official Python SDK ; OPA's Python integration is via a sidecar HTTP, which we'd also need.
- **Casbin** — popular Go library, also has Python bindings. Less batteries-included for the resource/principal/action model we need ; less audit-log integration ; less of a "tool the security team has heard of" outside Go shops.
- **Native Claude Code `permissions` settings** in `~/.claude/settings.json` — simpler but loses : audit log, conditional rules, policy-as-code review, and external review. The `settings.json` is co-located with user config, not a security artifact.
- **Hardcoded Python policy rules** in the broker — fast to build, but : not Git-reviewable by sec team, not lintable, not signable. Also drifts as the codebase grows ("oh, just one more if-branch" → unaudited surface).

## References

- Cerbos — https://cerbos.dev
- CNCF Sandbox project page — https://www.cncf.io/projects/cerbos/
- CEL (Common Expression Language) — https://github.com/google/cel-spec
- Related ADRs : [0002](0002-pretooluse-hook-as-interception-point.md), [0006](0006-host-side-broker.md), [0008](0008-pin-upstream-images-and-deps.md), [0010](0010-network-egress-filter-allowlist.md)
- Threat model use of Cerbos — [`docs/security/threat-model.md`](../security/threat-model.md) §5
- Controls matrix mapping — [`docs/security/controls-matrix.md`](../security/controls-matrix.md) (OWASP A01, NIST PW.4)

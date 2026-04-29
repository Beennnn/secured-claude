# 21. Pin Claude Code npm version + Renovate auto-bump

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0008](0008-pin-upstream-images-and-deps.md) requires "every upstream image and dep digest-pinned" for supply-chain integrity. v0.1 + v0.2 honoured this for :

- `cerbos/cerbos:0.42.0@sha256:...` ✓
- `node:22-slim@sha256:...` ✓
- `alpine:3.20@sha256:...` ✓
- `aquasec/trivy:0.69.3` ✓
- `gcr.io/kaniko-project/executor:v1.23.2-debug` ✓
- Python deps via `uv.lock` ✓

But the **Claude Code npm package itself** stayed pinned to `@latest` :

```dockerfile
RUN npm install -g --no-audit --no-fund @anthropic-ai/claude-code@latest
```

This violated the ADR-0008 contract for the single most important application dependency in the project — the agent binary the entire policy stack exists to wrap.

Concrete risks of `@latest` for `@anthropic-ai/claude-code` :

1. **Non-reproducible builds** — `secured-claude/claude-code:v0.2.0` built today and rebuilt next month are different binaries. An audit of "what shipped in v0.2.0" would only see "whatever was latest on 2026-04-29".
2. **No audit trail of Claude Code version per release** — a compliance review can't answer "did we test secured-claude v0.2.0 against Claude Code 2.1.50 or 2.2.0 ?".
3. **Supply-chain attack window** — if an attacker compromised the `@anthropic-ai/claude-code` npm package and published a malicious version, our next CI rebuild silently shipped it. With a pin, the malicious version requires an explicit Renovate PR that gates through CI before landing.
4. **No way to roll back Claude Code without rolling back secured-claude** — pinning means we can ship `secured-claude v0.2.1` that downgrades the Claude Code pin if 2.2.0 is broken.

## Decision

Adopt three pieces in lockstep :

### 1. Pin the version via a Dockerfile `ARG`

```dockerfile
ARG CLAUDE_CODE_VERSION=2.1.123
RUN npm install -g --no-audit --no-fund "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force
```

Why an `ARG` rather than a hardcoded string : `bin/update-claude-code.sh` (below) uses `sed` against the `ARG CLAUDE_CODE_VERSION=` line, and the same `ARG` lets a developer build with `--build-arg CLAUDE_CODE_VERSION=2.2.0-rc1` for ad-hoc audit testing without modifying the Dockerfile.

### 2. Renovate `customManagers` regex manager

`renovate.json` declares :

```json
"customManagers": [{
  "customType": "regex",
  "managerFilePatterns": ["/^Dockerfile\\.claude-code$/"],
  "matchStrings": [
    "ARG CLAUDE_CODE_VERSION=(?<currentValue>[0-9][^\\s]*)"
  ],
  "datasourceTemplate": "npm",
  "depNameTemplate": "@anthropic-ai/claude-code"
}]
```

Renovate's standard managers don't recognise the npm package because it lives in a Dockerfile RUN line, not a package.json. The regex manager bridges that : on every Renovate run, Renovate queries `https://registry.npmjs.org/@anthropic-ai/claude-code/latest`, compares to the pinned version, and opens a PR with the bump.

A `packageRules` entry pins the bump to `groupName: "Claude Code CLI"` so the PR shows up labelled `claude-code-bump` and isn't auto-merged (Anthropic occasionally ships breaking tool changes that need policy review — see ADR-0003 default-deny on unknown_tool).

### 3. `bin/update-claude-code.sh` for the impatient path

Renovate runs once a week (`schedule: ["before 6am on monday"]`). When Anthropic ships a critical fix, that's too slow.

The script automates the manual bump :
1. Queries `registry.npmjs.org` for the latest version.
2. Compares to the current `ARG CLAUDE_CODE_VERSION=` value.
3. If different : edits the ARG, builds the image locally, runs `claude --version` inside, runs `bin/test-egress.sh` (L2 + L3 regression check).
4. On green : prints the diff, optionally commits.

The script has three modes :
- `--check` (default for CI / cron) : print delta, don't build/edit.
- `--yes` : auto-commit to dev (still requires manual push + MR).
- (no flag) : interactive ; prompt before commit.

## Consequences

**Positive** :
- ADR-0008 contract is now genuinely whole — no `@latest` anywhere in our image build.
- Each `secured-claude vX.Y.Z` release has a deterministic, auditable Claude Code version baked in. `git show vX.Y.Z:Dockerfile.claude-code | grep CLAUDE_CODE_VERSION` answers the compliance question.
- Renovate-mediated bumps go through the full CI gate (lint + test + security + L2/L3 enforcement test) before landing — same protection as any other dep bump.
- `bin/update-claude-code.sh` makes ad-hoc bumps a 60-second operation.

**Negative — what becomes harder or riskier** :
- Anthropic's release cadence is high (multiple versions per week). Renovate may open many PRs ; we group them via `groupName: "Claude Code CLI"` so the dependency dashboard stays scannable.
- If Renovate is broken (unlikely — it's a hosted GitLab integration here), Claude Code falls behind silently. Mitigated by the script + a quarterly manual `bin/update-claude-code.sh --check` sanity check.

**Neutral** :
- The `ARG CLAUDE_CODE_VERSION` default in the Dockerfile is the canonical pin. CI builds use this value (no `--build-arg` override). Local dev builds with `docker build --build-arg CLAUDE_CODE_VERSION=2.2.0-rc1` are clearly marked as off-canon by their build args.

## Verification

- **Renovate dry-run** (manual once on first deploy) : `npx -y renovate --schedule "" --dry-run benoit.besson/secured-claude` confirms the customManager picks up the ARG and resolves a candidate PR.
- **Script smoke test** :
  ```
  $ bin/update-claude-code.sh --check
  ===== query npm registry =====
    latest published : 2.1.123
    pinned in repo   : 2.1.123
    ✓ already on latest — nothing to do.
  ```
- **Build smoke** : `docker build -f Dockerfile.claude-code .` produces an image with the pinned Claude Code version, verifiable by `docker run --rm <image> claude --version`.

## Alternatives considered

- **Maintain a `package.json` for Claude Code separately** — would let standard Renovate (npm manager) pick it up. But adds a misleading file (the project isn't a Node project) and a `npm install` step that's redundant with the existing `npm install -g`. Rejected.
- **Use `npm install -g @anthropic-ai/claude-code@^2.1`** (caret range) — softer pin, allows minor bumps automatically. Rejected for the same reason `@latest` was rejected : non-determinism in CI rebuilds. We want exact pinning + Renovate as the "controlled bump" mechanism.
- **GitHub Actions instead of Renovate** — actions/check-for-update style. Out of scope for this project's GitLab-only CI/CD policy (see CLAUDE.md).
- **Skip pinning, document the `@latest` risk in SECURITY.md as a known limitation** — what v0.1 + v0.2 did. The ADR-0008 contract makes this technical debt rather than a documented choice.

## References

- [ADR-0008](0008-pin-upstream-images-and-deps.md) — the "pin everything" contract this ADR honours
- [ADR-0014](0014-gitlab-ci-pipeline-6-stages.md) — CI gate that bump PRs go through
- [`renovate.json`](../../renovate.json) — customManagers + packageRules for Claude Code + Cerbos + alpine
- [`bin/update-claude-code.sh`](../../bin/update-claude-code.sh) — the impatient-bump path
- npm registry : https://registry.npmjs.org/@anthropic-ai/claude-code

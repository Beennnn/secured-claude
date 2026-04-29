# ADR-0014: GitLab CI pipeline — 6 stages, audit-demo gates releases

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

A CI pipeline is the **operational backbone of the security posture** : it's where pinning is enforced, scans run, signatures applied, and releases produced. A weak CI undoes everything.

Constraints :

- The project must build, test, scan, and publish on every push to `dev` and on every tag.
- Security-relevant scans (`bandit`, `pip-audit`, `trivy`, `grype`, `gitleaks`, `audit-demo --strict`) must be **gates**, not warnings.
- Pipelines should be cheap (no SaaS Windows runners — paid quota is finite).
- Conventional Commits validated on every push.
- Release artifacts (Python wheel, Docker image, install scripts) signed and SBOM-attached.

## Decision

We adopt a **6-stage GitLab CI pipeline** :

```
lint → test → security → build → publish → release
```

### Stage descriptions

| Stage | Jobs | Gate behavior |
|---|---|---|
| **lint** | `ruff check`, `ruff format --check`, `mypy --strict`, `hadolint`, `shellcheck`, `cerbos compile policies/`, `commitlint` (Conventional Commits) | All must pass — non-zero blocks subsequent stages |
| **test** | `pytest -m "not audit"` matrix on Python 3.11, 3.12, 3.13 | Coverage threshold (TBD, target 80%+) |
| **security** | `bandit -r src/`, `pip-audit`, `gitleaks detect`, `trivy image $IMG --severity HIGH,CRITICAL`, `grype dir:.`, `secured-claude audit-demo --strict` | **Hard gate** — any HIGH/CRITICAL CVE or red-team scenario passing blocks the pipeline |
| **build** | `uv build` → wheel + sdist ; `docker buildx build --platform linux/amd64,linux/arm64` | Artifacts attached |
| **publish** (only on tags) | Push image to GitLab Container Registry (digest pinned) ; upload wheel to GitLab Package Registry (PyPI-format) ; cosign keyless sign image ; syft generate SBOM (SPDX) | Only runs on `vX.Y.Z` tags |
| **release** (only on tags) | `release-cli` creates GitLab Release with assets : wheel, sdist, install scripts, SBOM, audit-demo report ; CHANGELOG generated from Conventional Commits | Tag annotation pushed alongside the release |

### Key rules

- **No SaaS Windows runners** — we use GitLab Linux shared runners (free tier sufficient) ; cross-OS testing is manual on Mac (host) + post-release Windows.
- **No `allow_failure: true`** — per CLAUDE.md global rule, any "shield" needs a dated TODO and ADR justification.
- **Branch protection** — `main` rejects direct push ; merge requires green pipeline + maintainer approval.
- **`only_allow_merge_if_pipeline_succeeds: true`** — set on the GitLab project.
- **`only_allow_merge_if_all_discussions_are_resolved: true`** — set on the project.
- **Pipeline timeout** — 1 hour default, generous enough for image build + scans.

### CI variables hygiene

- `ANTHROPIC_API_KEY` is **not** a CI variable in v0.1 (CI doesn't run audit-demo against the real Claude — it uses mocked Cerbos responses).
- `CI_REGISTRY` + `CI_REGISTRY_IMAGE` + `CI_JOB_TOKEN` come from GitLab built-ins, scoped to current pipeline.
- `SIGSTORE_ID_TOKEN` (cosign keyless OIDC) requested via `id_tokens:` block on the publish stage.
- All sensitive variables (cosign config if any, SonarCloud token v0.2+) marked `protected: true` (only on protected refs : `main` and tags) and `masked: true` (redacted in logs).

## Consequences

### Positive

- **Security stage gates releases** — a broken `audit-demo` blocks the tag, prevents shipping a regressed security posture.
- **Conventional Commits enforced** — semver bumps deterministic, CHANGELOG auto-generation works.
- **Reproducible artifacts** — same source + same CI = same wheel + same image digest.
- **Cosign + SBOM for free** — every release ships with cryptographic provenance.
- **Aligns with NIST SSDF v1.1 PW.6 (Configure compilation, interpreter, build processes to improve executable security) and PS.2 (Provide a mechanism for verifying release integrity)**.
- **GitLab-native** — uses platform features (Container Registry, Package Registry, Release CLI, ID tokens) without adding third-party dependencies.

### Negative

- **Pipeline length** — 6 stages, ~10-15 min wall-time end-to-end. Mitigated by : (a) parallel jobs within stages, (b) caching Python deps via uv, (c) Docker buildx layer cache.
- **No Windows CI** — Windows-specific bugs caught only at release time. Acceptable for v0.1 portfolio scale ; v0.2+ may add a Windows manual job if user feedback demands.
- **Renovate noise** — auto-PRs every week. Mitigated by auto-merge for safe categories.
- **Conventional Commits learning curve** — contributors new to CC need a quick orientation. Mitigated by `CLAUDE.md` project-level snippet + commitlint clear errors.

### Neutral

- We accept that the security stage is the longest (~5 min for trivy + grype + audit-demo). It's the most important stage so it gets the budget.

## Alternatives considered

- **GitHub Actions** as primary CI — disqualified by CLAUDE.md global rule. Mirror only.
- **Drone CI / CircleCI / Buildkite** — lock-in tradeoffs, none clearly better for our scale. Rejected.
- **Single-stage pipeline** (everything inline in `script:`) — works for tiny projects but : (a) no parallelism, (b) hard to see "which check failed" at a glance, (c) reruns the world on every change. Rejected.
- **More granular stages** (pre-lint, lint, type-check, unit-test, integ-test, …) — fragmentation without payoff for our scale. 6 stages is the sweet spot.
- **Audit-demo as a separate weekly scheduled job** instead of a release gate — less protection. The point of audit-demo is "every release passes red-team" — running it weekly leaves a window for a bad release to ship. Rejected.

## References

- GitLab CI/CD architecture — https://docs.gitlab.com/ee/ci/yaml/
- NIST SSDF v1.1 (SP 800-218) — https://csrc.nist.gov/Projects/ssdf
- Conventional Commits 1.0 — https://www.conventionalcommits.org/en/v1.0.0/
- GitLab CI ID tokens for OIDC — https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html
- Implementation : [`.gitlab-ci.yml`](../../.gitlab-ci.yml), [`renovate.json`](../../renovate.json)
- Related ADRs : [0008](0008-pin-upstream-images-and-deps.md) (pinning enforced in CI), [0015](0015-distribution-pipx-gitlab-registry.md) (publish targets), [0016](0016-supply-chain-cosign-sbom.md) (cosign signing in publish)
